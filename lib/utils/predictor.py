#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import re
import threading

from lib.core.data import kb
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths


class TrieNode(object):
    """
    Node for a prefix Trie optimized for prefix-based candidate lookup
    """

    __slots__ = ("children", "is_end", "value", "weight")

    def __init__(self):
        self.children = {}
        self.is_end = False
        self.value = None
        self.weight = 0


class PredictionTrie(object):
    """
    Trie structure that supports:
    - Prefix search with weighted results
    - Case-insensitive matching with original case preservation
    - Length filtering
    """

    def __init__(self):
        self.root = TrieNode()
        self._size = 0
        self._lock = threading.Lock()

    def insert(self, word, weight=1):
        """
        Insert a word into the trie with a given weight

        >>> t = PredictionTrie()
        >>> t.insert("users", 10)
        >>> t.search_prefix("us")
        [('users', 10)]
        """

        if not word:
            return

        with self._lock:
            node = self.root
            key = word.lower()

            for char in key:
                if char not in node.children:
                    node.children[char] = TrieNode()
                node = node.children[char]

            if not node.is_end:
                self._size += 1

            node.is_end = True
            node.value = word  # preserve original case
            node.weight = max(node.weight, weight)

    def search_prefix(self, prefix, max_results=10, length_filter=None):
        """
        Find all words starting with prefix, sorted by weight descending.
        Optionally filter by exact length.

        >>> t = PredictionTrie()
        >>> t.insert("users", 10)
        >>> t.insert("username", 5)
        >>> t.insert("uploads", 3)
        >>> t.search_prefix("user")
        [('users', 10), ('username', 5)]
        >>> t.search_prefix("user", length_filter=5)
        [('users', 10)]
        """

        if not prefix:
            return []

        node = self.root
        key = prefix.lower()

        for char in key:
            if char not in node.children:
                return []
            node = node.children[char]

        results = []
        # Collect with a cap to avoid traversing huge subtrees
        # We collect more than max_results to allow for length filtering and sorting
        collect_limit = max_results * 10 if length_filter is None else max_results * 20
        self._collect(node, results, length_filter, collect_limit)

        results.sort(key=lambda x: -x[1])
        return results[:max_results]

    def _collect(self, node, results, length_filter=None, limit=500):
        """
        Collect words from a given node using iterative DFS with limit.
        """

        stack = [node]
        while stack and len(results) < limit:
            current = stack.pop()
            if current.is_end:
                if length_filter is None or len(current.value) == length_filter:
                    results.append((current.value, current.weight))
            for child in current.children.values():
                stack.append(child)

    def __len__(self):
        return self._size


class SchemaPredictor(object):
    """
    Multi-layer prediction engine for SQL blind inference optimization.

    Layers (in priority order):
    1. Schema learning: names discovered in current session
    2. Naming pattern analysis: prefixes, suffixes, separators from findings
    3. Static dictionaries: common-tables.txt, common-columns.txt, common-outputs.txt
    4. Language dictionaries: common words in EN/ES for table/column naming
    """

    # Common words used in database naming (English)
    ENGLISH_DB_WORDS = (
        "account", "accounts", "action", "actions", "address", "addresses",
        "admin", "admins", "alert", "alerts", "api", "app", "apps",
        "article", "articles", "asset", "assets", "attachment", "attachments",
        "audit", "audits", "auth", "authentication",
        "backup", "backups", "badge", "badges", "balance", "balances",
        "billing", "blog", "blogs", "bookmark", "bookmarks", "brand", "brands",
        "budget", "budgets",
        "cache", "calendar", "campaign", "campaigns", "card", "cards",
        "cart", "carts", "catalog", "category", "categories", "change", "changes",
        "channel", "channels", "chat", "chats", "checkout", "city", "cities",
        "claim", "claims", "client", "clients", "code", "codes",
        "collection", "collections", "color", "colors", "comment", "comments",
        "company", "companies", "config", "configuration", "configurations",
        "connection", "connections", "contact", "contacts", "content", "contents",
        "contract", "contracts", "conversation", "conversations", "country", "countries",
        "coupon", "coupons", "course", "courses", "credential", "credentials",
        "credit", "credits", "currency", "currencies", "customer", "customers",
        "dashboard", "dashboards", "data", "database", "databases",
        "department", "departments", "deposit", "deposits", "detail", "details",
        "device", "devices", "discount", "discounts", "document", "documents",
        "domain", "domains", "download", "downloads",
        "email", "emails", "employee", "employees", "entry", "entries",
        "error", "errors", "event", "events", "export", "exports",
        "feature", "features", "feed", "feedback", "feedbacks", "file", "files",
        "filter", "filters", "flag", "flags", "folder", "folders",
        "form", "forms", "forum", "forums", "friend", "friends",
        "gallery", "galleries", "game", "games", "gateway", "gateways",
        "grant", "grants", "group", "groups", "guest", "guests",
        "history", "histories", "hook", "hooks",
        "image", "images", "import", "imports", "inbox", "index",
        "industry", "industries", "integration", "integrations",
        "inventory", "inventories", "invoice", "invoices", "issue", "issues",
        "item", "items",
        "job", "jobs", "journal", "journals",
        "key", "keys",
        "label", "labels", "language", "languages", "lead", "leads",
        "level", "levels", "license", "licenses", "like", "likes",
        "link", "links", "list", "lists", "location", "locations",
        "log", "login", "logins", "logs", "lookup", "lookups",
        "mail", "mails", "manager", "managers", "map", "maps",
        "media", "member", "members", "membership", "memberships",
        "menu", "menus", "merchant", "merchants", "message", "messages",
        "metadata", "metric", "metrics", "migration", "migrations",
        "module", "modules", "monitor", "monitors",
        "name", "names", "news", "newsletter", "newsletters",
        "note", "notes", "notification", "notifications", "number", "numbers",
        "offer", "offers", "option", "options", "order", "orders",
        "organization", "organizations", "output", "outputs",
        "package", "packages", "page", "pages", "parameter", "parameters",
        "partner", "partners", "password", "passwords", "path", "paths",
        "payment", "payments", "people", "permission", "permissions",
        "person", "persons", "phone", "phones", "photo", "photos",
        "pipeline", "pipelines", "plan", "plans", "platform", "platforms",
        "player", "players", "plugin", "plugins", "point", "points",
        "policy", "policies", "poll", "polls", "pool", "pools",
        "position", "positions", "post", "posts", "preference", "preferences",
        "price", "prices", "priority", "priorities", "process", "processes",
        "product", "products", "profile", "profiles", "program", "programs",
        "project", "projects", "promotion", "promotions", "property", "properties",
        "provider", "providers", "purchase", "purchases",
        "query", "queries", "queue", "queues", "question", "questions", "quote", "quotes",
        "rate", "rates", "rating", "ratings", "receipt", "receipts",
        "record", "records", "refund", "refunds", "region", "regions",
        "registration", "registrations", "relationship", "relationships",
        "reminder", "reminders", "reply", "replies", "report", "reports",
        "request", "requests", "reservation", "reservations",
        "resource", "resources", "response", "responses", "result", "results",
        "return", "returns", "review", "reviews", "revision", "revisions",
        "reward", "rewards", "role", "roles", "room", "rooms", "route", "routes",
        "rule", "rules",
        "sale", "sales", "schedule", "schedules", "schema", "schemas",
        "score", "scores", "search", "searches", "section", "sections",
        "security", "segment", "segments", "server", "servers",
        "service", "services", "session", "sessions", "setting", "settings",
        "shipment", "shipments", "shipping", "shop", "shops", "site", "sites",
        "skill", "skills", "snapshot", "snapshots", "source", "sources",
        "staff", "stage", "stages", "state", "states", "statistics",
        "status", "statuses", "step", "steps", "stock", "stocks",
        "store", "stores", "story", "stories", "stream", "streams",
        "student", "students", "subscription", "subscriptions",
        "summary", "summaries", "supplier", "suppliers", "support", "survey", "surveys",
        "system", "systems",
        "table", "tables", "tag", "tags", "target", "targets",
        "task", "tasks", "tax", "taxes", "team", "teams",
        "template", "templates", "tenant", "tenants", "term", "terms",
        "territory", "territories", "test", "tests", "text", "texts",
        "theme", "themes", "thread", "threads", "ticket", "tickets",
        "tier", "tiers", "time", "timeline", "timelines", "times",
        "title", "titles", "token", "tokens", "topic", "topics",
        "total", "totals", "tracking", "trade", "trades",
        "transaction", "transactions", "transfer", "transfers",
        "translation", "translations", "trigger", "triggers",
        "type", "types",
        "unit", "units", "update", "updates", "upload", "uploads",
        "url", "urls", "usage", "user", "users",
        "value", "values", "variable", "variables", "vendor", "vendors",
        "version", "versions", "video", "videos", "view", "views",
        "visit", "visits", "visitor", "visitors", "voucher", "vouchers",
        "wallet", "wallets", "warehouse", "warehouses",
        "webhook", "webhooks", "website", "websites", "widget", "widgets",
        "wishlist", "wishlists", "withdrawal", "withdrawals",
        "word", "words", "workflow", "workflows", "workspace", "workspaces",
        "zone", "zones",
    )

    # Common words used in database naming (Spanish)
    SPANISH_DB_WORDS = (
        "acceso", "accesos", "accion", "acciones", "actividad", "actividades",
        "administrador", "administradores", "agenda", "agendas",
        "alerta", "alertas", "almacen", "almacenes", "alumno", "alumnos",
        "aplicacion", "aplicaciones", "archivo", "archivos", "area", "areas",
        "articulo", "articulos", "asignacion", "asignaciones",
        "auditoria", "auditorias",
        "banco", "bancos", "beneficio", "beneficios", "bitacora", "bitacoras",
        "calendario", "calendarios", "campo", "campos", "cargo", "cargos",
        "carrito", "carritos", "catalogo", "catalogos",
        "categoria", "categorias", "ciudad", "ciudades",
        "cliente", "clientes", "cobro", "cobros", "codigo", "codigos",
        "comentario", "comentarios", "compania", "companias",
        "compra", "compras", "comunicacion", "comunicaciones",
        "concepto", "conceptos", "configuracion", "configuraciones",
        "contacto", "contactos", "contrato", "contratos",
        "control", "controles", "correo", "correos",
        "cuenta", "cuentas", "cuota", "cuotas", "curso", "cursos",
        "dato", "datos", "departamento", "departamentos",
        "deposito", "depositos", "descuento", "descuentos",
        "detalle", "detalles", "direccion", "direcciones",
        "documento", "documentos", "domicilio", "domicilios",
        "dominio", "dominios",
        "empleado", "empleados", "empresa", "empresas",
        "encuesta", "encuestas", "entidad", "entidades",
        "entrada", "entradas", "envio", "envios",
        "equipo", "equipos", "error", "errores",
        "estado", "estados", "evento", "eventos",
        "factura", "facturas", "familia", "familias",
        "fecha", "fechas", "folio", "folios", "formulario", "formularios",
        "foto", "fotos", "funcion", "funciones",
        "gasto", "gastos", "grupo", "grupos",
        "herramienta", "herramientas", "historial", "historiales",
        "horario", "horarios",
        "imagen", "imagenes", "impuesto", "impuestos",
        "indicador", "indicadores", "informe", "informes",
        "ingreso", "ingresos", "inscripcion", "inscripciones",
        "institucion", "instituciones", "inventario", "inventarios",
        "licitacion", "licitaciones", "lista", "listas",
        "log", "logs", "lugar", "lugares",
        "marca", "marcas", "materia", "materias",
        "medio", "medios", "mensaje", "mensajes", "menu", "menus",
        "meta", "metas", "metodo", "metodos", "modulo", "modulos",
        "moneda", "monedas", "movimiento", "movimientos",
        "municipio", "municipios",
        "nivel", "niveles", "nombre", "nombres", "nota", "notas",
        "noticia", "noticias", "notificacion", "notificaciones",
        "numero", "numeros",
        "oferta", "ofertas", "opcion", "opciones",
        "operacion", "operaciones", "orden", "ordenes",
        "organizacion", "organizaciones",
        "pago", "pagos", "pais", "paises", "paquete", "paquetes",
        "parametro", "parametros", "partida", "partidas",
        "pedido", "pedidos", "perfil", "perfiles",
        "periodo", "periodos", "permiso", "permisos",
        "persona", "personas", "plan", "planes",
        "plataforma", "plataformas", "plaza", "plazas",
        "poliza", "polizas", "precio", "precios",
        "pregunta", "preguntas", "presupuesto", "presupuestos",
        "proceso", "procesos", "producto", "productos",
        "profesor", "profesores", "programa", "programas",
        "proyecto", "proyectos", "publicacion", "publicaciones",
        "puesto", "puestos", "punto", "puntos",
        "recibo", "recibos", "recurso", "recursos",
        "red", "redes", "referencia", "referencias",
        "region", "regiones", "registro", "registros",
        "regla", "reglas", "relacion", "relaciones",
        "reporte", "reportes", "reserva", "reservas",
        "respuesta", "respuestas", "resultado", "resultados",
        "rol", "roles", "rubro", "rubros", "ruta", "rutas",
        "salario", "salarios", "seccion", "secciones",
        "seguimiento", "seguimientos", "servicio", "servicios",
        "sesion", "sesiones", "sistema", "sistemas",
        "solicitud", "solicitudes", "sucursal", "sucursales",
        "tarea", "tareas", "tarifa", "tarifas",
        "telefono", "telefonos", "tema", "temas",
        "ticket", "tickets", "tienda", "tiendas",
        "tipo", "tipos", "titulo", "titulos",
        "total", "totales", "trabajo", "trabajos",
        "transaccion", "transacciones", "turno", "turnos",
        "ubicacion", "ubicaciones", "unidad", "unidades",
        "usuario", "usuarios",
        "valor", "valores", "venta", "ventas",
        "version", "versiones", "viaje", "viajes",
        "zona", "zonas",
    )

    # Common words used in database naming (Portuguese)
    PORTUGUESE_DB_WORDS = (
        "acesso", "acessos", "aluno", "alunos", "arquivo", "arquivos",
        "avaliacao", "avaliacoes",
        "cadastro", "cadastros", "cargo", "cargos", "carrinho", "carrinhos",
        "cidade", "cidades", "cliente", "clientes", "cobranca", "cobrancas",
        "comentario", "comentarios", "compra", "compras",
        "configuracao", "configuracoes", "conta", "contas",
        "contato", "contatos", "contrato", "contratos",
        "cupom", "cupons", "curso", "cursos",
        "dado", "dados", "departamento", "departamentos",
        "desconto", "descontos", "documento", "documentos",
        "empresa", "empresas", "endereco", "enderecos",
        "entrega", "entregas", "equipe", "equipes",
        "estoque", "estoques", "evento", "eventos",
        "fatura", "faturas", "fornecedor", "fornecedores",
        "foto", "fotos", "funcionario", "funcionarios",
        "grupo", "grupos",
        "historico", "historicos", "horario", "horarios",
        "imagem", "imagens", "imposto", "impostos",
        "item", "itens", "loja", "lojas", "log", "logs",
        "marca", "marcas", "mensagem", "mensagens",
        "meta", "metas", "modulo", "modulos",
        "movimentacao", "movimentacoes",
        "notificacao", "notificacoes", "numero", "numeros",
        "oferta", "ofertas", "orcamento", "orcamentos",
        "pagamento", "pagamentos", "parceiro", "parceiros",
        "pedido", "pedidos", "perfil", "perfis",
        "permissao", "permissoes", "pessoa", "pessoas",
        "plano", "planos", "produto", "produtos",
        "projeto", "projetos", "promocao", "promocoes",
        "receita", "receitas", "registro", "registros",
        "relatorio", "relatorios", "reserva", "reservas",
        "resultado", "resultados",
        "servico", "servicos", "sessao", "sessoes",
        "sistema", "sistemas",
        "tarefa", "tarefas", "taxa", "taxas",
        "transacao", "transacoes", "turma", "turmas",
        "unidade", "unidades", "usuario", "usuarios",
        "venda", "vendas", "versao", "versoes",
    )

    # Known framework tables (Django, Rails, Laravel)
    FRAMEWORK_TABLES = (
        # === DJANGO ===
        "auth_group", "auth_group_permissions", "auth_permission",
        "auth_user", "auth_user_groups", "auth_user_user_permissions",
        "django_admin_log", "django_content_type", "django_migrations",
        "django_session", "django_site",
        "account_emailaddress", "account_emailconfirmation",
        "socialaccount_socialaccount", "socialaccount_socialapp",
        "socialaccount_socialtoken",
        # === RAILS ===
        "active_storage_attachments", "active_storage_blobs",
        "active_storage_variant_records", "action_text_rich_texts",
        "ar_internal_metadata", "schema_migrations", "friendly_id_slugs",
        # === LARAVEL ===
        "password_resets", "password_reset_tokens", "failed_jobs",
        "personal_access_tokens", "job_batches", "cache_locks",
        "telescope_entries", "telescope_entries_tags", "telescope_monitoring",
        "nova_notifications", "nova_field_attachments", "action_events",
        "oauth_access_tokens", "oauth_auth_codes", "oauth_clients",
        "oauth_personal_access_clients", "oauth_refresh_tokens",
        "role_has_permissions", "model_has_permissions", "model_has_roles",
        "subscription_items",
        # === WORDPRESS CORE ===
        "wp_users", "wp_usermeta", "wp_posts", "wp_postmeta",
        "wp_comments", "wp_commentmeta", "wp_options", "wp_links",
        "wp_terms", "wp_term_taxonomy", "wp_term_relationships", "wp_termmeta",
        # WooCommerce
        "wp_woocommerce_sessions", "wp_woocommerce_api_keys",
        "wp_woocommerce_attribute_taxonomies",
        "wp_woocommerce_downloadable_product_permissions",
        "wp_woocommerce_order_items", "wp_woocommerce_order_itemmeta",
        "wp_woocommerce_tax_rates", "wp_woocommerce_tax_rate_locations",
        "wp_woocommerce_shipping_zones", "wp_woocommerce_shipping_zone_methods",
        "wp_woocommerce_shipping_zone_locations",
        "wp_woocommerce_payment_tokens", "wp_woocommerce_payment_tokenmeta",
        "wp_woocommerce_log",
        "wp_wc_product_meta_lookup", "wp_wc_tax_rate_classes",
        "wp_wc_reserved_stock", "wp_wc_webhooks", "wp_wc_download_log",
        "wp_wc_admin_notes", "wp_wc_admin_note_actions",
        "wp_wc_order_stats", "wp_wc_order_product_lookup",
        "wp_wc_order_tax_lookup", "wp_wc_order_coupon_lookup",
        "wp_wc_category_lookup",
        # Yoast SEO
        "wp_yoast_seo_links", "wp_yoast_seo_meta",
        "wp_yoast_indexable", "wp_yoast_indexable_hierarchy",
        "wp_yoast_migrations", "wp_yoast_primary_term",
        # WPForms / Gravity Forms
        "wp_wpforms_entries", "wp_wpforms_entry_meta", "wp_wpforms_entry_fields",
        "wp_gf_form", "wp_gf_form_meta", "wp_gf_entry", "wp_gf_entry_meta",
        # bbPress / BuddyPress
        "wp_bbp_replies", "wp_bbp_topics",
        "wp_bp_activity", "wp_bp_groups", "wp_bp_members", "wp_bp_messages",
        # Redirection / Wordfence
        "wp_redirection_items", "wp_redirection_logs", "wp_redirection_groups",
        "wp_wfconfig", "wp_wfhits", "wp_wflogins", "wp_wfissues",
        # === JOOMLA (jos_ prefix) ===
        "jos_users", "jos_session", "jos_content", "jos_categories",
        "jos_extensions", "jos_menu", "jos_menu_types",
        "jos_modules", "jos_modules_menu", "jos_template_styles",
        "jos_assets", "jos_usergroups", "jos_user_usergroup_map",
        "jos_viewlevels", "jos_languages", "jos_schemas",
        "jos_redirect_links", "jos_tags", "jos_contentitem_tag_map",
        "jos_ucm_content", "jos_ucm_history",
        "jos_fields", "jos_fields_categories", "jos_fields_groups",
        "jos_fields_values", "jos_action_logs", "jos_action_log_config",
        "jos_privacy_consents", "jos_privacy_requests",
        "jos_mail_templates", "jos_workflow_stages",
        "jos_workflow_transitions", "jos_workflows",
        "jos_banners", "jos_banner_clients", "jos_banner_tracks",
        "jos_contact_details", "jos_newsfeeds", "jos_finder_terms",
        # === DRUPAL ===
        "node", "node_field_data", "node_revision",
        "users_field_data", "user_roles",
        "comment_field_data", "taxonomy_term_data",
        "taxonomy_term_field_data", "taxonomy_term_hierarchy",
        "taxonomy_vocabulary", "file_managed", "file_usage",
        "menu_tree", "menu_link_content_data",
        "block_content", "block_content_field_data", "path_alias",
        "shortcut_set_users", "key_value", "key_value_expire",
        "cache_default", "cache_entity", "cache_discovery",
        "cache_bootstrap", "cache_config", "cache_data",
        "cache_render", "cache_page", "watchdog",
        # === MAGENTO ===
        "admin_user", "admin_passwords",
        "authorization_role", "authorization_rule",
        "customer_entity", "customer_address_entity", "customer_group",
        "catalog_product_entity", "catalog_product_entity_varchar",
        "catalog_product_entity_int", "catalog_product_entity_decimal",
        "catalog_product_entity_text", "catalog_product_entity_datetime",
        "catalog_category_entity", "catalog_category_product",
        "catalog_product_link", "catalog_product_website",
        "eav_attribute", "eav_attribute_set", "eav_entity_type",
        "sales_order", "sales_order_item", "sales_order_address",
        "sales_order_payment", "sales_order_status", "sales_order_grid",
        "sales_invoice", "sales_invoice_item", "sales_shipment",
        "sales_creditmemo", "quote_item", "quote_address",
        "store_group", "store_website",
        "cms_page", "cms_block", "url_rewrite",
        "email_template", "newsletter_subscriber",
        "core_config_data", "setup_module", "cron_schedule",
        "indexer_state", "mview_state", "cache_tag",
        "search_query", "catalogsearch_fulltext",
        "review_detail", "wishlist_item",
        # === PRESTASHOP (ps_ prefix) ===
        "ps_customer", "ps_address", "ps_orders", "ps_order_detail",
        "ps_order_history", "ps_cart", "ps_cart_product",
        "ps_product", "ps_product_lang", "ps_product_attribute",
        "ps_category", "ps_category_lang", "ps_category_product",
        "ps_manufacturer", "ps_supplier", "ps_currency",
        "ps_country", "ps_state", "ps_zone", "ps_tax", "ps_tax_rule",
        "ps_carrier", "ps_delivery", "ps_employee", "ps_shop",
        "ps_configuration", "ps_lang", "ps_meta",
        "ps_cms", "ps_cms_lang", "ps_page", "ps_page_viewed",
        "ps_image", "ps_stock_available", "ps_specific_price",
        "ps_hook", "ps_hook_module", "ps_module", "ps_tab",
        "ps_attribute", "ps_attribute_group", "ps_feature",
        "ps_feature_value", "ps_feature_product", "ps_search_word",
        "ps_connections", "ps_guest", "ps_referrer",
        # === MOODLE (mdl_ prefix) ===
        "mdl_user", "mdl_course", "mdl_course_categories",
        "mdl_course_modules", "mdl_course_sections",
        "mdl_enrol", "mdl_user_enrolments",
        "mdl_role", "mdl_role_assignments", "mdl_context",
        "mdl_grade_items", "mdl_grade_grades", "mdl_grade_categories",
        "mdl_assign", "mdl_assign_submission", "mdl_assign_grades",
        "mdl_quiz", "mdl_quiz_attempts", "mdl_question", "mdl_question_answers",
        "mdl_forum", "mdl_forum_discussions", "mdl_forum_posts",
        "mdl_files", "mdl_config", "mdl_config_plugins",
        "mdl_logstore_standard_log", "mdl_sessions",
        "mdl_groups", "mdl_groups_members", "mdl_modules",
        "mdl_block_instances", "mdl_capabilities", "mdl_event",
        "mdl_message", "mdl_message_contacts", "mdl_notification",
        # === GHOST CMS ===
        "posts_tags", "roles_users", "permissions_users",
        "permissions_roles", "members_labels",
        "stripe_products", "stripe_prices", "custom_theme_settings",
        # === STRAPI ===
        "strapi_users", "strapi_roles", "strapi_permissions",
        "strapi_webhooks", "strapi_files", "strapi_api_tokens",
        "up_users", "up_roles", "up_permissions", "upload_folders",
        # === MEDIAWIKI ===
        "categorylinks", "pagelinks", "templatelinks", "externallinks",
        "interwiki", "recentchanges", "objectcache",
        "querycache", "searchindex", "site_stats",
        "ipblocks", "filearchive", "uploadstash",
        # === PHPBB (phpbb_ prefix) ===
        "phpbb_users", "phpbb_groups", "phpbb_forums", "phpbb_topics",
        "phpbb_posts", "phpbb_config", "phpbb_sessions",
        "phpbb_acl_groups", "phpbb_acl_options", "phpbb_acl_roles",
        "phpbb_banlist", "phpbb_bookmarks", "phpbb_drafts",
        "phpbb_log", "phpbb_modules", "phpbb_privmsgs",
        "phpbb_reports", "phpbb_smilies", "phpbb_styles",
        "phpbb_warnings", "phpbb_words", "phpbb_zebra",
        # === NEXTCLOUD (oc_ prefix) ===
        "oc_users", "oc_groups", "oc_group_user", "oc_accounts",
        "oc_preferences", "oc_appconfig", "oc_storages",
        "oc_filecache", "oc_mimetypes", "oc_share",
        "oc_activity", "oc_comments", "oc_cards", "oc_calendars",
        "oc_calendarobjects", "oc_addressbooks", "oc_jobs",
        # === DISCOURSE ===
        "topic_tags", "user_emails", "user_profiles", "user_stats",
        "site_settings", "user_badges",
        # === SPRING BOOT ===
        "hibernate_sequence",
        "SPRING_SESSION", "SPRING_SESSION_ATTRIBUTES",
        "BATCH_JOB_INSTANCE", "BATCH_JOB_EXECUTION",
        "BATCH_STEP_EXECUTION", "BATCH_JOB_EXECUTION_PARAMS",
        "BATCH_STEP_EXECUTION_CONTEXT",
        # === COMMON ORM / MIGRATION ===
        "migrations", "schema_info", "schema_version",
        "flyway_schema_history", "databasechangelog",

        # === SUITECRM / SUGARCRM (CVE-2024-36412 and others) ===
        "accounts", "accounts_contacts", "accounts_opportunities",
        "accounts_bugs", "accounts_cases", "accounts_cstm",
        "calls", "calls_contacts", "calls_users", "calls_leads",
        "campaigns", "campaign_log", "campaign_trkrs",
        "cases", "cases_bugs", "contacts", "contacts_cstm",
        "contracts", "documents", "document_revisions",
        "email_addresses", "email_addr_bean_rel", "emails",
        "emails_text", "email_marketing", "email_templates",
        "inbound_email", "leads", "leads_cstm",
        "meetings", "meetings_contacts", "meetings_users", "meetings_leads",
        "notes", "opportunities", "opportunities_contacts",
        "opportunities_cstm", "project", "project_task",
        "prospects", "prospect_lists", "prospect_lists_prospects",
        "tasks", "users", "user_preferences",
        "acl_actions", "acl_roles", "acl_roles_actions", "acl_roles_users",
        "bugs", "bugs_cstm", "config", "currencies",
        "custom_fields", "fields_meta_data",
        "relationships", "relationship_type",
        "saved_search", "schedulers", "schedulers_times",
        "sugarfeed", "tracker", "trackers",
        "upgrade_history", "user_signatures", "vcals",

        # === VTIGER CRM (CVE-2019-11057, CVE-2023-38891) ===
        "vtiger_users", "vtiger_account", "vtiger_accountcf",
        "vtiger_accountbillads", "vtiger_accountshipads",
        "vtiger_contactdetails", "vtiger_contactsubdetails",
        "vtiger_contactaddress", "vtiger_contactscf",
        "vtiger_leaddetails", "vtiger_leadsubdetails",
        "vtiger_leadaddress", "vtiger_leadscf",
        "vtiger_potential", "vtiger_potentialscf",
        "vtiger_products", "vtiger_productcf",
        "vtiger_service", "vtiger_servicecf",
        "vtiger_invoice", "vtiger_invoicecf",
        "vtiger_salesorder", "vtiger_purchaseorder",
        "vtiger_quotes", "vtiger_quotescf",
        "vtiger_vendor", "vtiger_vendorcf",
        "vtiger_campaign", "vtiger_campaignscf",
        "vtiger_troubletickets", "vtiger_ticketcf",
        "vtiger_faq", "vtiger_attachments",
        "vtiger_notes", "vtiger_notescf",
        "vtiger_activity", "vtiger_activitycf",
        "vtiger_seactivityrel", "vtiger_cntactivityrel",
        "vtiger_crmentity", "vtiger_crmentitynotesrel",
        "vtiger_tab", "vtiger_field", "vtiger_blocks",
        "vtiger_picklist", "vtiger_role", "vtiger_role2picklist",
        "vtiger_user2role", "vtiger_profile", "vtiger_profile2field",
        "vtiger_def_org_field", "vtiger_org_share_action_mapping",
        "vtiger_audit_trial", "vtiger_loginhistory",
        "vtiger_systems", "vtiger_organizationdetails",
        "vtiger_currency_info", "vtiger_relatedlists",
        "vtiger_entityname", "vtiger_modentity_num",
        "vtiger_customview", "vtiger_cvcolumnlist",

        # === DOLIBARR ERP/CRM (CVE-2018-10094 and others) ===
        "llx_user", "llx_societe", "llx_socpeople",
        "llx_commande", "llx_commandedet", "llx_facture",
        "llx_facturedet", "llx_propal", "llx_propaldet",
        "llx_product", "llx_product_price",
        "llx_categorie", "llx_categorie_product",
        "llx_bank", "llx_bank_account", "llx_paiement",
        "llx_expedition", "llx_expeditiondet",
        "llx_contrat", "llx_contratdet",
        "llx_projet", "llx_projet_task",
        "llx_actioncomm", "llx_const",
        "llx_menu", "llx_rights_def", "llx_usergroup",
        "llx_usergroup_user", "llx_usergroup_rights",
        "llx_c_country", "llx_c_departements", "llx_c_regions",
        "llx_c_currencies", "llx_c_tva",
        "llx_element_element", "llx_entity",

        # === ORANGEHRM (multiple SQLi CVEs) ===
        "ohrm_user", "ohrm_user_role", "ohrm_employee",
        "ohrm_emp_work_experience", "ohrm_emp_education",
        "ohrm_emp_skill", "ohrm_emp_language",
        "ohrm_emp_emergency_contacts", "ohrm_emp_dependents",
        "ohrm_leave", "ohrm_leave_type", "ohrm_leave_entitlement",
        "ohrm_leave_request", "ohrm_attendance_record",
        "ohrm_timesheet", "ohrm_timesheet_item",
        "ohrm_job_title", "ohrm_job_category",
        "ohrm_subunit", "ohrm_location", "ohrm_nationality",
        "ohrm_pay_grade", "ohrm_pay_grade_currency",
        "ohrm_performance_review", "ohrm_reviewer",
        "hs_hr_employee", "hs_hr_module",

        # === MANTIS BT (multiple SQLi CVEs) ===
        "mantis_user_table", "mantis_bug_table",
        "mantis_bugnote_table", "mantis_bugnote_text_table",
        "mantis_project_table", "mantis_project_hierarchy_table",
        "mantis_project_user_list_table", "mantis_category_table",
        "mantis_bug_history_table", "mantis_bug_file_table",
        "mantis_bug_text_table", "mantis_bug_relationship_table",
        "mantis_bug_tag_table", "mantis_tag_table",
        "mantis_custom_field_table", "mantis_custom_field_string_table",
        "mantis_config_table", "mantis_filters_table",
        "mantis_tokens_table", "mantis_user_pref_table",

        # === OSCOMMERCE (classic SQLi target) ===
        "administrators", "address_book", "categories",
        "categories_description", "configuration", "configuration_group",
        "countries", "currencies", "customers", "customers_basket",
        "customers_info", "languages", "manufacturers",
        "manufacturers_info", "orders", "orders_products",
        "orders_products_attributes", "orders_status",
        "orders_status_history", "orders_total",
        "products", "products_attributes", "products_description",
        "products_images", "products_options",
        "products_options_values", "products_to_categories",
        "reviews", "reviews_description", "sessions",
        "specials", "tax_class", "tax_rates",
        "whos_online", "zones",

        # === OPENCART (multiple SQLi CVEs) ===
        "oc_customer", "oc_customer_group", "oc_customer_ip",
        "oc_customer_login", "oc_customer_online",
        "oc_order", "oc_order_history", "oc_order_option",
        "oc_order_product", "oc_order_total", "oc_order_voucher",
        "oc_product", "oc_product_description", "oc_product_image",
        "oc_product_option", "oc_product_option_value",
        "oc_product_to_category", "oc_product_to_store",
        "oc_category", "oc_category_description",
        "oc_manufacturer", "oc_setting", "oc_user",
        "oc_user_group", "oc_session", "oc_cart",
        "oc_coupon", "oc_coupon_history", "oc_voucher",
        "oc_review", "oc_return", "oc_currency",
        "oc_language", "oc_store", "oc_zone",
        "oc_country", "oc_tax_class", "oc_tax_rate",
        "oc_extension", "oc_module", "oc_event",

        # === GLPI (CVE-2022-35914 and others) ===
        "glpi_users", "glpi_profiles", "glpi_profiles_users",
        "glpi_entities", "glpi_computers", "glpi_monitors",
        "glpi_networkequipments", "glpi_peripherals", "glpi_phones",
        "glpi_printers", "glpi_softwares", "glpi_softwareversions",
        "glpi_tickets", "glpi_ticketfollowups",
        "glpi_tickettasks", "glpi_ticketvalidations",
        "glpi_changes", "glpi_problems",
        "glpi_groups", "glpi_groups_users",
        "glpi_locations", "glpi_states",
        "glpi_manufacturers", "glpi_suppliers",
        "glpi_contracts", "glpi_documents",
        "glpi_knowbaseitems", "glpi_events", "glpi_logs",
        "glpi_configs", "glpi_crontasks",

        # === CACTI (CVE-2024-25641, CVE-2023-49084) ===
        "user_auth", "user_auth_perms", "user_auth_realm",
        "user_auth_group", "user_auth_group_members",
        "user_auth_group_perms", "user_auth_group_realm",
        "data_local", "data_template_data", "data_template_rrd",
        "data_source", "data_input", "data_input_data",
        "graph_local", "graph_templates",
        "graph_templates_item", "graph_templates_graph",
        "graph_tree", "graph_tree_items",
        "host", "host_template", "host_snmp_cache",
        "poller", "poller_item", "poller_output",
        "cdef", "cdef_items", "colors",
        "settings", "settings_user", "sessions",
        "version", "automation_templates",

        # === ZABBIX (multiple SQLi historically) ===
        "users", "usrgrp", "users_groups",
        "hosts", "hosts_groups", "hstgrp",
        "items", "triggers", "functions",
        "events", "alerts", "actions",
        "conditions", "operations", "media",
        "media_type", "screens", "graphs",
        "graphs_items", "sysmaps", "config",
        "globalmacro", "hostmacro", "profiles",
        "scripts", "maintenances", "services",
        "sessions", "auditlog", "acknowledges",
    )

    # Known Hungarian notation prefixes (tbl, vw, sp, fn, etc.)
    HUNGARIAN_PREFIXES = ("tbl", "vw", "sp", "fn", "usp", "udf", "pkg", "trg")

    # Common column name components
    COLUMN_COMPONENTS = (
        "id", "name", "type", "status", "code", "date", "time", "timestamp",
        "created", "updated", "deleted", "modified", "active", "enabled",
        "description", "title", "value", "key", "level", "order", "sort",
        "count", "total", "amount", "price", "cost", "quantity", "size",
        "width", "height", "length", "weight", "color", "url", "path",
        "email", "phone", "address", "city", "state", "country", "zip",
        "first", "last", "middle", "full", "display", "short", "long",
        "start", "end", "begin", "min", "max", "avg", "sum",
        "is", "has", "can", "flag", "bool",
        "parent", "child", "owner", "author", "creator", "editor",
        "source", "target", "origin", "dest", "ref", "foreign",
        "hash", "token", "salt", "secret", "password", "passwd",
        "lat", "lng", "latitude", "longitude", "geo",
        "note", "comment", "memo", "text", "body", "content",
        "image", "photo", "avatar", "icon", "logo", "thumbnail",
        "file", "filename", "filepath", "extension", "mime",
        "ip", "host", "port", "domain", "protocol", "method",
        "version", "revision", "number", "index", "position", "rank",
        "role", "group", "team", "org", "company", "dept",
        "at", "on", "by", "for", "from", "to", "in",
    )

    # Weight constants for prediction sources
    WEIGHT_SCHEMA_LEARNING = 100  # highest priority - from current session
    WEIGHT_CMS_DETECTED = 90     # CMS detected via fingerprint - very high confidence
    WEIGHT_PATTERN_DERIVED = 80   # derived from naming patterns
    WEIGHT_COLUMN_CONTEXT = 75    # column predicted from known table context
    WEIGHT_COMMON_OUTPUTS = 60    # from common-outputs.txt
    WEIGHT_STATIC_DICT = 40       # from common-tables/columns.txt
    WEIGHT_VALUE_PREDICT = 35     # predicted data values (status, email domains, etc.)
    WEIGHT_LANGUAGE_DICT = 20     # from language dictionaries

    # CMS fingerprint tables: if ANY of these exist, we know the CMS
    CMS_FINGERPRINTS = {
        "wordpress": ["wp_options", "wp_posts", "wp_users"],
        "joomla": ["jos_extensions", "jos_users", "jos_content"],
        "drupal": ["node", "node_field_data", "watchdog"],
        "magento": ["catalog_product_entity", "eav_attribute", "core_config_data"],
        "prestashop": ["ps_configuration", "ps_customer", "ps_orders"],
        "moodle": ["mdl_config", "mdl_user", "mdl_course"],
        "django": ["django_migrations", "auth_user", "django_content_type"],
        "laravel": ["migrations", "failed_jobs", "personal_access_tokens"],
        "rails": ["schema_migrations", "ar_internal_metadata", "active_storage_blobs"],
        "phpbb": ["phpbb_users", "phpbb_config", "phpbb_forums"],
        "nextcloud": ["oc_users", "oc_appconfig", "oc_filecache"],
        "suitecrm": ["accounts", "contacts", "email_addr_bean_rel"],
        "vtiger": ["vtiger_users", "vtiger_crmentity", "vtiger_tab"],
        "dolibarr": ["llx_user", "llx_societe", "llx_const"],
        "glpi": ["glpi_users", "glpi_tickets", "glpi_computers"],
        "mantis": ["mantis_user_table", "mantis_bug_table", "mantis_project_table"],
        "mediawiki": ["page", "revision", "interwiki"],
        "ghost": ["posts", "posts_tags", "roles_users"],
    }

    # HTTP fingerprints for passive CMS detection from headers/cookies/body
    HTTP_FINGERPRINTS = {
        "wordpress": {
            "headers": ["x-powered-by: php", "link: <.*wp-json"],
            "cookies": ["wordpress_logged_in", "wordpress_test_cookie", "wp-settings"],
            "body": ["/wp-content/", "/wp-includes/", "/wp-admin/", "wp-login.php",
                     "WordPress", "/xmlrpc.php"],
        },
        "joomla": {
            "headers": [],
            "cookies": ["joomla_user_state", "jpanesliders"],
            "body": ["/administrator/", "/components/com_", "/modules/mod_",
                     "Joomla!", "/media/jui/", "option=com_"],
        },
        "drupal": {
            "headers": ["x-drupal-cache", "x-drupal-dynamic-cache", "x-generator: drupal"],
            "cookies": ["SESSa", "SSESSa", "Drupal.visitor"],
            "body": ["/sites/default/files/", "/core/misc/drupal.js",
                     "Drupal.settings", "drupal.org", "/core/misc/drupal.js"],
        },
        "magento": {
            "headers": ["x-magento-vary"],
            "cookies": ["PHPSESSID", "mage-cache-storage", "mage-messages",
                         "form_key", "mage-cache-sessid"],
            "body": ["/skin/frontend/", "/media/catalog/", "Mage.Cookies",
                     "Magento_Ui", "/checkout/cart/"],
        },
        "django": {
            "headers": [],
            "cookies": ["csrftoken", "django_language", "sessionid"],
            "body": ["csrfmiddlewaretoken", "__admin/", "django"],
        },
        "laravel": {
            "headers": [],
            "cookies": ["laravel_session", "XSRF-TOKEN"],
            "body": ["laravel", "csrf-token"],
        },
        "rails": {
            "headers": ["x-powered-by: phusion passenger", "x-runtime"],
            "cookies": ["_session_id"],
            "body": ["authenticity_token", "csrf-token", "rails"],
        },
        "prestashop": {
            "headers": ["powered-by: prestashop"],
            "cookies": ["PrestaShop"],
            "body": ["/modules/", "/themes/", "prestashop", "id_product"],
        },
        "moodle": {
            "headers": [],
            "cookies": ["MoodleSession"],
            "body": ["/course/view.php", "/mod/", "/login/index.php", "moodle"],
        },
        "phpbb": {
            "headers": [],
            "cookies": ["phpbb_sid", "phpbb_u", "phpbb_k"],
            "body": ["phpBB", "viewtopic.php", "viewforum.php", "memberlist.php"],
        },
        "nextcloud": {
            "headers": [],
            "cookies": ["nc_session_id", "oc_sessionPassphrase"],
            "body": ["nextcloud", "/ocs/v2.php", "/remote.php/"],
        },
        "mediawiki": {
            "headers": ["x-powered-by: mediawiki"],
            "cookies": ["mediawiki", "wikiSession"],
            "body": ["mediawiki", "wgArticleId", "/wiki/", "Special:"],
        },
    }

    # Common database names for CMS/frameworks
    CMS_DATABASE_NAMES = {
        "wordpress": [
            "wordpress", "wp", "wp_database", "wpdb", "wp_site",
            "bitnami_wordpress", "wordpress_db", "wpsite",
            "blog", "blog_db", "website", "cms",
        ],
        "joomla": [
            "joomla", "joomla_db", "joomladb", "joomla_site",
            "bitnami_joomla", "cms", "website",
        ],
        "drupal": [
            "drupal", "drupal_db", "drupaldb", "drupal_site",
            "bitnami_drupal", "cms", "website",
        ],
        "magento": [
            "magento", "magento_db", "magentodb", "magento2",
            "bitnami_magento", "ecommerce", "shop", "store",
        ],
        "prestashop": [
            "prestashop", "prestashop_db", "presta", "presta_shop",
            "bitnami_prestashop", "ecommerce", "shop", "store",
        ],
        "moodle": [
            "moodle", "moodle_db", "moodledb", "bitnami_moodle",
            "lms", "elearning", "campus",
        ],
        "django": [
            "django", "django_db", "djangodb", "app", "webapp",
            "backend", "api_db", "project",
        ],
        "laravel": [
            "laravel", "laravel_db", "forge", "homestead",
            "app", "webapp", "backend", "api",
        ],
        "rails": [
            "rails", "rails_db", "app_development", "app_production",
            "webapp", "backend",
        ],
        "phpbb": [
            "phpbb", "phpbb_db", "phpbb3", "forum", "forum_db",
            "community", "board",
        ],
        "nextcloud": [
            "nextcloud", "nextcloud_db", "owncloud", "cloud",
        ],
        "suitecrm": [
            "suitecrm", "suitecrm_db", "sugarcrm", "crm", "crm_db",
        ],
        "vtiger": [
            "vtiger", "vtigercrm", "vtiger_db", "crm", "vtigercrm6", "vtigercrm7",
        ],
        "dolibarr": [
            "dolibarr", "dolibarr_db", "dolidb", "erp", "erp_db",
        ],
        "glpi": [
            "glpi", "glpi_db", "glpidb", "itsm", "helpdesk",
        ],
        "mantis": [
            "mantis", "mantisbt", "bugtracker", "mantis_db",
        ],
        "mediawiki": [
            "mediawiki", "wikidb", "wiki", "my_wiki",
        ],
        "ghost": [
            "ghost", "ghost_db", "ghostdb", "blog",
        ],
    }

    # Common generic database names (not CMS-specific)
    COMMON_DATABASE_NAMES = (
        "information_schema", "mysql", "performance_schema", "sys",
        "master", "tempdb", "model", "msdb",
        "postgres", "template0", "template1",
        "admin", "app", "application", "api",
        "backend", "cms", "crm", "erp",
        "blog", "forum", "wiki", "portal",
        "database", "db", "data", "main",
        "dev", "development", "staging", "production", "test",
        "ecommerce", "shop", "store", "marketplace",
        "hr", "finance", "accounting", "inventory",
        "security", "auth", "users", "accounts",
        "webapp", "website", "site", "web",
        "reports", "analytics", "logs", "audit",
        "backup", "archive", "legacy", "old",
    )

    # Table -> known columns mapping for CMS/frameworks
    TABLE_COLUMNS = {
        # WordPress
        "wp_users": ["ID", "user_login", "user_pass", "user_nicename", "user_email",
                      "user_url", "user_registered", "user_activation_key",
                      "user_status", "display_name"],
        "wp_posts": ["ID", "post_author", "post_date", "post_content", "post_title",
                      "post_excerpt", "post_status", "comment_status", "ping_status",
                      "post_password", "post_name", "post_modified", "post_type",
                      "post_mime_type", "comment_count"],
        "wp_options": ["option_id", "option_name", "option_value", "autoload"],
        "wp_comments": ["comment_ID", "comment_post_ID", "comment_author",
                         "comment_author_email", "comment_author_url",
                         "comment_date", "comment_content", "comment_approved"],
        "wp_usermeta": ["umeta_id", "user_id", "meta_key", "meta_value"],
        "wp_postmeta": ["meta_id", "post_id", "meta_key", "meta_value"],
        "wp_terms": ["term_id", "name", "slug", "term_group"],
        "wp_term_taxonomy": ["term_taxonomy_id", "term_id", "taxonomy", "description", "parent", "count"],
        # Django
        "auth_user": ["id", "password", "last_login", "is_superuser", "username",
                       "first_name", "last_name", "email", "is_staff", "is_active",
                       "date_joined"],
        "auth_group": ["id", "name"],
        "auth_permission": ["id", "name", "content_type_id", "codename"],
        "django_content_type": ["id", "app_label", "model"],
        "django_migrations": ["id", "app", "name", "applied"],
        "django_session": ["session_key", "session_data", "expire_date"],
        # Joomla
        "jos_users": ["id", "name", "username", "email", "password", "block",
                       "sendEmail", "registerDate", "lastvisitDate", "activation",
                       "params", "lastResetTime", "resetCount", "otpKey", "otep", "requireReset"],
        "jos_content": ["id", "title", "alias", "introtext", "fulltext",
                         "state", "catid", "created", "created_by", "modified",
                         "publish_up", "publish_down", "hits", "language"],
        "jos_extensions": ["extension_id", "name", "type", "element", "folder",
                            "client_id", "enabled", "access", "protected", "manifest_cache"],
        # Magento
        "admin_user": ["user_id", "firstname", "lastname", "email", "username",
                        "password", "created", "modified", "logdate", "lognum",
                        "reload_acl_flag", "is_active", "extra", "rp_token"],
        "customer_entity": ["entity_id", "website_id", "email", "group_id",
                             "store_id", "created_at", "updated_at", "is_active",
                             "disable_auto_group_change", "firstname", "lastname",
                             "password_hash", "rp_token", "default_billing", "default_shipping"],
        "sales_order": ["entity_id", "state", "status", "customer_id", "customer_email",
                         "customer_firstname", "customer_lastname", "grand_total",
                         "total_paid", "total_qty_ordered", "store_id", "created_at"],
        "catalog_product_entity": ["entity_id", "attribute_set_id", "type_id", "sku",
                                    "has_options", "required_options", "created_at", "updated_at"],
        # PrestaShop
        "ps_customer": ["id_customer", "id_shop", "id_gender", "id_default_group",
                         "firstname", "lastname", "email", "passwd", "birthday",
                         "newsletter", "ip_registration_newsletter", "optin",
                         "active", "date_add", "date_upd"],
        "ps_orders": ["id_order", "id_customer", "id_cart", "id_currency",
                       "id_carrier", "current_state", "payment", "total_paid",
                       "total_products", "date_add", "date_upd"],
        "ps_product": ["id_product", "id_supplier", "id_manufacturer", "id_category_default",
                        "id_tax_rules_group", "reference", "ean13", "price",
                        "wholesale_price", "quantity", "active", "date_add"],
        # Moodle
        "mdl_user": ["id", "username", "password", "firstname", "lastname",
                      "email", "city", "country", "lang", "timezone",
                      "firstaccess", "lastaccess", "lastlogin", "currentlogin",
                      "confirmed", "suspended", "deleted"],
        "mdl_course": ["id", "category", "sortorder", "fullname", "shortname",
                        "idnumber", "summary", "format", "startdate", "enddate",
                        "visible", "timecreated", "timemodified"],
        # phpBB
        "phpbb_users": ["user_id", "user_type", "group_id", "username",
                          "username_clean", "user_password", "user_email",
                          "user_birthday", "user_lastvisit", "user_posts",
                          "user_lang", "user_timezone", "user_avatar", "user_sig",
                          "user_regdate", "user_ip"],
        # vTiger
        "vtiger_users": ["id", "user_name", "user_password", "user_hash",
                          "first_name", "last_name", "email1", "email2",
                          "status", "is_admin", "currency_id", "date_format"],
        # SuiteCRM
        "users": ["id", "user_name", "user_hash", "system_generated_password",
                   "first_name", "last_name", "email1", "email2",
                   "status", "is_admin", "employee_status", "title",
                   "department", "phone_work", "phone_mobile"],
        "contacts": ["id", "first_name", "last_name", "email1", "phone_work",
                      "phone_mobile", "title", "department", "account_id",
                      "primary_address_street", "primary_address_city",
                      "primary_address_state", "primary_address_country"],
        # GLPI
        "glpi_users": ["id", "name", "password", "realname", "firstname",
                        "phone", "email", "is_active", "profiles_id",
                        "date_creation", "date_mod"],
        "glpi_tickets": ["id", "name", "date", "closedate", "solvedate",
                          "status", "users_id_recipient", "requesttypes_id",
                          "content", "urgency", "impact", "priority", "type"],
        # MantisBT
        "mantis_user_table": ["id", "username", "password", "email",
                                "realname", "access_level", "enabled",
                                "login_count", "last_visit", "date_created"],
        "mantis_bug_table": ["id", "project_id", "reporter_id", "handler_id",
                               "priority", "severity", "status", "resolution",
                               "summary", "description", "date_submitted", "last_updated"],
        # Nextcloud
        "oc_users": ["uid", "displayname", "password", "uid_lower"],
        # Dolibarr
        "llx_user": ["rowid", "login", "pass_crypted", "lastname", "firstname",
                      "email", "admin", "statut", "entity", "datec"],
        # Generic common tables
        "users": ["id", "username", "password", "email", "name", "role",
                   "status", "created_at", "updated_at", "last_login"],
        "accounts": ["id", "name", "email", "phone", "address", "city",
                      "state", "country", "status", "created_at"],
        "products": ["id", "name", "description", "price", "sku", "stock",
                      "category_id", "status", "created_at"],
        "orders": ["id", "user_id", "total", "status", "created_at", "updated_at"],
        "sessions": ["id", "user_id", "token", "ip_address", "expires_at"],
        "categories": ["id", "name", "description", "parent_id", "sort_order"],
        "comments": ["id", "post_id", "user_id", "body", "created_at"],
        "posts": ["id", "title", "body", "author_id", "status", "created_at"],
        "tags": ["id", "name", "slug"],
        "roles": ["id", "name", "description"],
        "permissions": ["id", "name", "description", "role_id"],
        "settings": ["id", "key", "value", "type"],
        "logs": ["id", "user_id", "action", "message", "ip_address", "created_at"],
        "notifications": ["id", "user_id", "type", "message", "read", "created_at"],
        "files": ["id", "name", "path", "size", "mime_type", "user_id", "created_at"],
        "migrations": ["id", "migration", "batch"],
    }

    # Common values for specific column types
    COLUMN_VALUE_PREDICTIONS = {
        # Status fields
        "status": ["active", "inactive", "pending", "deleted", "suspended",
                    "enabled", "disabled", "approved", "rejected", "draft",
                    "published", "archived", "cancelled", "completed", "processing",
                    "shipped", "delivered", "refunded", "failed", "expired"],
        "state": ["active", "inactive", "pending", "open", "closed",
                   "new", "in_progress", "resolved", "on_hold"],
        "post_status": ["publish", "draft", "pending", "private", "trash",
                         "auto-draft", "inherit", "future"],
        "comment_status": ["open", "closed"],
        "post_type": ["post", "page", "attachment", "revision", "nav_menu_item",
                       "custom_css", "customize_changeset", "product", "shop_order"],
        # Role fields
        "role": ["admin", "administrator", "editor", "author", "contributor",
                  "subscriber", "moderator", "manager", "user", "guest",
                  "superadmin", "operator", "viewer"],
        "user_type": ["admin", "user", "moderator", "guest"],
        "is_admin": ["0", "1", "yes", "no", "true", "false", "on"],
        "is_active": ["0", "1", "yes", "no", "true", "false"],
        # Language/locale
        "lang": ["en", "es", "fr", "de", "pt", "it", "nl", "ru", "zh", "ja",
                  "ko", "ar", "en-US", "en-GB", "es-ES", "fr-FR", "de-DE", "pt-BR"],
        "language": ["en-GB", "en-US", "es-ES", "fr-FR", "de-DE", "pt-BR",
                      "it-IT", "nl-NL", "ru-RU", "zh-CN", "ja-JP"],
        # Payment
        "payment": ["credit_card", "paypal", "bank_transfer", "cash",
                      "stripe", "check", "wire_transfer", "bitcoin"],
        "method": ["GET", "POST", "PUT", "DELETE", "PATCH", "credit_card", "paypal"],
        # Currency
        "currency_cd": ["USD", "EUR", "GBP", "MXN", "BRL", "ARS", "CLP",
                         "COP", "PEN", "UYU", "CAD", "AUD", "JPY", "CNY"],
        "iso_code": ["USD", "EUR", "GBP", "MXN", "BRL", "ARS"],
        # Country
        "country": ["United States", "Mexico", "Brazil", "Argentina", "Colombia",
                      "Spain", "United Kingdom", "France", "Germany", "Canada",
                      "Chile", "Peru", "Uruguay", "Italy", "Portugal"],
        # Email domains (for predicting after @)
        "_email_domain": ["gmail.com", "hotmail.com", "yahoo.com", "outlook.com",
                           "live.com", "mail.com", "protonmail.com", "icloud.com"],
        # Boolean-like
        "active": ["0", "1", "Y", "N", "yes", "no", "true", "false"],
        "enabled": ["0", "1", "Y", "N", "yes", "no"],
        "autoload": ["yes", "no"],
        "deleted": ["0", "1"],
        # Type fields
        "type": ["post", "page", "user", "comment", "product", "order",
                  "category", "tag", "file", "image", "text", "html"],
    }

    # URL/path column names that trigger URL predictions
    URL_COLUMN_NAMES = (
        "url", "link", "href", "uri", "path", "filepath", "file_path",
        "avatar", "avatar_url", "image", "image_url", "photo", "photo_url",
        "logo", "icon", "thumbnail", "banner", "cover",
        "user_url", "site_url", "home_url", "redirect_url",
        "source_url", "target_url", "callback_url", "return_url",
        "link_url", "website", "homepage",
    )

    # Column names that contain password hashes
    HASH_COLUMN_NAMES = (
        "password", "passwd", "pass", "user_pass", "user_password",
        "password_hash", "pass_hash", "pass_crypted",
        "user_hash", "pwd", "secret", "credential",
    )

    # Known hash type prefixes and their fixed structure
    # Each entry: (prefix, total_fixed_prefix_length, description)
    # The prefix is what gets inserted into the trie; the length helps skip chars
    HASH_TYPE_PREFIXES = {
        # bcrypt ($2a$, $2b$, $2y$ + 2-digit cost + $)
        "bcrypt": [
            "$2y$10$", "$2y$12$", "$2y$08$", "$2y$11$", "$2y$13$", "$2y$14$",
            "$2a$10$", "$2a$12$", "$2a$08$", "$2a$11$",
            "$2b$10$", "$2b$12$", "$2b$08$",
        ],
        # WordPress phpass ($P$B, $P$D + 1 char)
        "phpass": [
            "$P$B", "$P$D", "$P$9", "$P$C",
            "$H$B", "$H$D", "$H$9",
        ],
        # Django PBKDF2
        "django_pbkdf2": [
            "pbkdf2_sha256$", "pbkdf2_sha1$",
            "argon2$argon2id$",
            "bcrypt_sha256$$2b$",
        ],
        # MySQL native
        "mysql_native": [
            "*",  # MySQL 4.1+ native hash starts with *
        ],
        # MD5 ($1$)
        "md5_crypt": [
            "$1$",
        ],
        # SHA-256 crypt ($5$)
        "sha256_crypt": [
            "$5$rounds=",
            "$5$",
        ],
        # SHA-512 crypt ($6$)
        "sha512_crypt": [
            "$6$rounds=",
            "$6$",
        ],
        # Argon2
        "argon2": [
            "$argon2id$v=19$",
            "$argon2i$v=19$",
        ],
        # Laravel / Symfony (bcrypt wrapped)
        "laravel": [
            "$2y$10$", "$2y$12$",
        ],
    }

    # CMS-specific hash types (only loaded when CMS is detected)
    CMS_HASH_TYPES = {
        "wordpress": ["phpass"],
        "joomla": ["bcrypt"],
        "drupal": ["django_pbkdf2", "sha512_crypt"],  # Drupal 8+ uses phpass or argon2
        "magento": ["sha256_crypt", "bcrypt"],
        "prestashop": ["md5_crypt", "bcrypt"],
        "moodle": ["bcrypt", "md5_crypt"],
        "django": ["django_pbkdf2"],
        "laravel": ["laravel", "bcrypt"],
        "phpbb": ["phpass"],
        "suitecrm": ["md5_crypt"],
        "vtiger": ["md5_crypt"],
        "glpi": ["bcrypt"],
        "mantis": ["bcrypt"],
        "nextcloud": ["bcrypt", "argon2"],
    }

    # Column names that contain email addresses
    EMAIL_COLUMN_NAMES = (
        "email", "user_email", "email1", "email2", "mail",
        "email_address", "e_mail", "contact_email",
        "customer_email", "admin_email", "notification_email",
        "login_email", "primary_email", "secondary_email",
    )

    # Common email domains (loaded after @ is detected in partial value)
    EMAIL_DOMAINS = (
        # Top global
        "gmail.com", "hotmail.com", "yahoo.com", "outlook.com",
        "live.com", "icloud.com", "protonmail.com", "mail.com",
        "aol.com", "zoho.com", "yandex.com", "gmx.com",
        # Privacy / secure
        "proton.me", "pm.me", "tutanota.com", "tutamail.com",
        "fastmail.com", "hey.com", "mailfence.com", "posteo.de",
        "disroot.org", "riseup.net", "runbox.com",
        # Apple / Microsoft legacy
        "me.com", "mac.com", "msn.com", "live.co.uk",
        "windowslive.com", "passport.com",
        # Yahoo variants
        "ymail.com", "rocketmail.com", "yahoo.co.uk",
        "yahoo.co.jp", "yahoo.fr", "yahoo.de",
        # Regional popular
        "mail.ru", "yandex.ru", "rambler.ru", "bk.ru",
        "list.ru", "inbox.ru",
        "web.de", "gmx.de", "gmx.net", "freenet.de",
        "t-online.de", "arcor.de",
        "libero.it", "virgilio.it", "alice.it", "tin.it",
        "orange.fr", "wanadoo.fr", "free.fr", "sfr.fr",
        "laposte.net", "bbox.fr",
        "terra.com.br", "uol.com.br", "bol.com.br", "ig.com.br",
        "terra.com", "terra.es",
        # Business / ISP
        "comcast.net", "verizon.net", "att.net", "sbcglobal.net",
        "cox.net", "charter.net", "earthlink.net",
        "btinternet.com", "sky.com", "ntlworld.com",
        # Education / org
        "edu", "ac.uk", "edu.au",
    )

    # Hash structure: known total lengths and valid charsets per hash type
    # Used to (1) filter predictions by length and (2) restrict bisection charset
    HASH_STRUCTURES = {
        "bcrypt": {
            "length": 60,
            # bcrypt: $2y$10$ + 53 chars of [./A-Za-z0-9]
            "charset": "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$",
        },
        "phpass": {
            "length": 34,
            # phpass: $P$B + 30 chars of [./A-Za-z0-9]
            "charset": "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$PHB9CDH",
        },
        "md5_hex": {
            "length": 32,
            # Plain MD5 hex: 32 chars of [0-9a-f]
            "charset": "0123456789abcdef",
        },
        "sha1_hex": {
            "length": 40,
            # Plain SHA1 hex: 40 chars of [0-9a-f]
            "charset": "0123456789abcdef",
        },
        "sha256_hex": {
            "length": 64,
            # Plain SHA-256 hex: 64 chars of [0-9a-f]
            "charset": "0123456789abcdef",
        },
        "mysql_native": {
            "length": 41,
            # MySQL native: * + 40 hex chars
            "charset": "0123456789ABCDEF*",
        },
        "md5_crypt": {
            "length": 34,
            # $1$ + salt + $ + 22 hash chars
            "charset": "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$1",
        },
    }

    # Map CMS to their default hash structure
    CMS_HASH_STRUCTURE = {
        "wordpress": "phpass",
        "joomla": "bcrypt",
        "drupal": "bcrypt",
        "magento": "bcrypt",
        "prestashop": "md5_hex",  # older versions; newer use bcrypt
        "moodle": "bcrypt",
        "django": None,  # variable format (pbkdf2_sha256$iterations$salt$hash)
        "laravel": "bcrypt",
        "phpbb": "phpass",
        "suitecrm": "md5_hex",
        "vtiger": "md5_hex",
        "glpi": "bcrypt",
        "mantis": "bcrypt",
        "nextcloud": "bcrypt",
    }

    # Column names that contain IP addresses
    IP_COLUMN_NAMES = (
        "ip", "ip_address", "ipaddress", "ip_addr",
        "user_ip", "last_ip", "login_ip", "client_ip",
        "remote_ip", "remote_addr", "source_ip",
        "ip_registration_newsletter",  # PrestaShop
        "registration_ip", "signup_ip", "created_ip",
    )

    # Common IP prefixes for private networks and known ranges
    COMMON_IP_PREFIXES = (
        # Private ranges
        "192.168.1.", "192.168.0.", "192.168.10.", "192.168.100.",
        "10.0.0.", "10.0.1.", "10.1.0.", "10.10.0.", "10.10.1.",
        "172.16.0.", "172.16.1.", "172.17.0.", "172.31.0.",
        # Localhost
        "127.0.0.1",
        "::1",
        # Common public prefixes
        "200.", "201.", "186.", "190.",  # LATAM
        "82.", "83.", "84.", "85.", "86.", "87.", "88.", "89.",  # Europe
        "1.", "2.", "3.", "4.", "5.",  # Various
    )

    # IP charset (only digits and dots for IPv4)
    IP_CHARSET = "0123456789.:"

    # Generic URL/path prefixes (always loaded for URL columns)
    GENERIC_URL_PREFIXES = (
        "http://", "https://", "ftp://",
        "/images/", "/img/", "/assets/", "/static/",
        "/uploads/", "/files/", "/media/",
        "/css/", "/js/", "/fonts/",
        "/api/", "/api/v1/", "/api/v2/",
        "/admin/", "/login/", "/dashboard/",
    )

    # CMS-specific URL/path prefixes (only loaded when CMS is detected)
    CMS_URL_PREFIXES = {
        "wordpress": [
            "/wp-content/uploads/", "/wp-content/themes/",
            "/wp-content/plugins/", "/wp-includes/",
            "/wp-admin/", "/wp-login.php",
            "/wp-content/uploads/woocommerce_uploads/",
            "/wp-json/", "/wp-json/wp/v2/",
            "https://wordpress.org/", "https://woocommerce.com/",
        ],
        "joomla": [
            "/components/", "/modules/", "/plugins/",
            "/media/", "/templates/", "/administrator/",
            "/images/", "/cache/", "/tmp/",
        ],
        "drupal": [
            "/sites/default/files/", "/sites/all/",
            "/core/", "/modules/contrib/", "/themes/",
            "/node/", "/admin/", "/user/",
        ],
        "magento": [
            "/media/catalog/product/", "/media/catalog/category/",
            "/skin/frontend/", "/skin/adminhtml/",
            "/pub/media/", "/pub/static/",
            "/static/frontend/", "/checkout/",
        ],
        "prestashop": [
            "/img/p/", "/img/c/", "/img/m/",
            "/modules/", "/themes/", "/upload/",
            "/download/", "/pdf/",
        ],
        "moodle": [
            "/pluginfile.php/", "/draftfile.php/",
            "/theme/", "/lib/", "/mod/",
            "/course/", "/user/",
        ],
        "django": [
            "/static/", "/media/",
            "/admin/", "/api/",
        ],
        "laravel": [
            "/storage/", "/public/",
            "/api/", "/admin/",
        ],
        "phpbb": [
            "/images/avatars/", "/images/smilies/",
            "/styles/", "/ext/",
        ],
        "nextcloud": [
            "/remote.php/dav/", "/remote.php/webdav/",
            "/ocs/v2.php/", "/index.php/apps/",
            "/core/img/", "/apps/",
        ],
    }

    # Quick schema tables: exact table lists per CMS for --quick-schema mode
    # These are the tables that exist in a DEFAULT installation
    QUICK_SCHEMA_TABLES = {
        "wordpress": [
            "wp_commentmeta", "wp_comments", "wp_links", "wp_options",
            "wp_postmeta", "wp_posts", "wp_term_relationships",
            "wp_term_taxonomy", "wp_termmeta", "wp_terms",
            "wp_usermeta", "wp_users",
            # WooCommerce (if installed)
            "wp_woocommerce_sessions", "wp_woocommerce_api_keys",
            "wp_woocommerce_attribute_taxonomies",
            "wp_woocommerce_order_items", "wp_woocommerce_order_itemmeta",
            "wp_woocommerce_tax_rates", "wp_woocommerce_shipping_zones",
            "wp_woocommerce_payment_tokens", "wp_woocommerce_log",
            "wp_wc_product_meta_lookup", "wp_wc_order_stats",
            "wp_wc_order_product_lookup", "wp_wc_category_lookup",
            # Yoast SEO
            "wp_yoast_seo_links", "wp_yoast_seo_meta",
            "wp_yoast_indexable", "wp_yoast_migrations",
            # Common plugins
            "wp_wpforms_entries", "wp_redirection_items",
            "wp_wfconfig", "wp_wfhits",
            "wp_gf_form", "wp_gf_entry",
        ],
        "joomla": [
            "jos_users", "jos_session", "jos_content", "jos_categories",
            "jos_extensions", "jos_menu", "jos_menu_types",
            "jos_modules", "jos_template_styles", "jos_assets",
            "jos_usergroups", "jos_user_usergroup_map", "jos_viewlevels",
            "jos_languages", "jos_tags", "jos_fields",
            "jos_action_logs", "jos_workflows", "jos_banners",
            "jos_contact_details", "jos_newsfeeds",
        ],
        "drupal": [
            "node", "node_field_data", "node_revision",
            "users", "users_field_data", "user_roles",
            "comment", "comment_field_data",
            "taxonomy_term_data", "taxonomy_term_field_data", "taxonomy_vocabulary",
            "file_managed", "file_usage", "menu_link_content_data",
            "block_content", "path_alias", "key_value",
            "cache_default", "cache_entity", "cache_config",
            "cache_data", "cache_render", "cache_page",
            "watchdog", "sessions", "flood",
        ],
        "magento": [
            "admin_user", "admin_passwords",
            "customer_entity", "customer_address_entity", "customer_group",
            "catalog_product_entity", "catalog_category_entity",
            "catalog_category_product", "eav_attribute", "eav_attribute_set",
            "sales_order", "sales_order_item", "sales_order_payment",
            "sales_invoice", "sales_shipment",
            "quote", "quote_item", "store", "store_website",
            "cms_page", "cms_block", "core_config_data",
            "cron_schedule", "newsletter_subscriber",
            "url_rewrite", "search_query", "wishlist",
        ],
        "prestashop": [
            "ps_customer", "ps_address", "ps_orders", "ps_order_detail",
            "ps_cart", "ps_product", "ps_product_lang",
            "ps_category", "ps_category_lang",
            "ps_manufacturer", "ps_supplier", "ps_currency",
            "ps_country", "ps_employee", "ps_configuration",
            "ps_lang", "ps_module", "ps_hook",
            "ps_image", "ps_stock_available",
        ],
        "moodle": [
            "mdl_user", "mdl_course", "mdl_course_categories",
            "mdl_course_modules", "mdl_course_sections",
            "mdl_enrol", "mdl_user_enrolments",
            "mdl_role", "mdl_role_assignments", "mdl_context",
            "mdl_grade_items", "mdl_grade_grades",
            "mdl_assign", "mdl_assign_submission",
            "mdl_quiz", "mdl_quiz_attempts",
            "mdl_forum", "mdl_forum_discussions", "mdl_forum_posts",
            "mdl_config", "mdl_logstore_standard_log",
            "mdl_sessions", "mdl_modules", "mdl_files",
            "mdl_groups", "mdl_message", "mdl_notification",
        ],
        "django": [
            "auth_group", "auth_group_permissions", "auth_permission",
            "auth_user", "auth_user_groups", "auth_user_user_permissions",
            "django_admin_log", "django_content_type",
            "django_migrations", "django_session", "django_site",
        ],
        "phpbb": [
            "phpbb_users", "phpbb_groups", "phpbb_forums", "phpbb_topics",
            "phpbb_posts", "phpbb_config", "phpbb_sessions",
            "phpbb_acl_groups", "phpbb_acl_options", "phpbb_acl_roles",
            "phpbb_banlist", "phpbb_bookmarks", "phpbb_drafts",
            "phpbb_log", "phpbb_privmsgs", "phpbb_styles",
        ],
        "vtiger": [
            "vtiger_users", "vtiger_account", "vtiger_contactdetails",
            "vtiger_leaddetails", "vtiger_potential", "vtiger_products",
            "vtiger_invoice", "vtiger_salesorder", "vtiger_quotes",
            "vtiger_vendor", "vtiger_campaign", "vtiger_troubletickets",
            "vtiger_crmentity", "vtiger_tab", "vtiger_field",
            "vtiger_role", "vtiger_currency_info",
        ],
        "glpi": [
            "glpi_users", "glpi_profiles", "glpi_profiles_users",
            "glpi_entities", "glpi_computers", "glpi_monitors",
            "glpi_printers", "glpi_softwares", "glpi_tickets",
            "glpi_ticketfollowups", "glpi_tickettasks",
            "glpi_groups", "glpi_locations", "glpi_suppliers",
            "glpi_documents", "glpi_configs", "glpi_logs",
        ],
        "mantis": [
            "mantis_user_table", "mantis_bug_table",
            "mantis_bugnote_table", "mantis_bugnote_text_table",
            "mantis_project_table", "mantis_category_table",
            "mantis_bug_history_table", "mantis_bug_file_table",
            "mantis_bug_text_table", "mantis_bug_tag_table",
            "mantis_tag_table", "mantis_custom_field_table",
            "mantis_config_table", "mantis_tokens_table",
            "mantis_filters_table",
        ],
        "suitecrm": [
            "accounts", "calls", "campaigns", "cases",
            "contacts", "documents", "email_addresses",
            "emails", "leads", "meetings", "notes",
            "opportunities", "prospects", "tasks", "users",
            "acl_roles", "bugs", "tracker",
        ],
        "dolibarr": [
            "llx_user", "llx_societe", "llx_socpeople",
            "llx_commande", "llx_commandedet",
            "llx_facture", "llx_facturedet",
            "llx_propal", "llx_product", "llx_product_price",
            "llx_categorie", "llx_bank_account", "llx_bank",
            "llx_paiement", "llx_projet", "llx_const",
            "llx_usergroup",
        ],
        "nextcloud": [
            "oc_users", "oc_groups", "oc_group_user", "oc_accounts",
            "oc_preferences", "oc_appconfig", "oc_storages",
            "oc_filecache", "oc_mimetypes", "oc_share",
            "oc_activity", "oc_comments", "oc_calendars",
            "oc_addressbooks", "oc_jobs",
        ],
    }

    # Minimum prefix length to attempt prediction
    MIN_PREFIX_LENGTH = 2

    # Maximum candidates to verify via SQL query
    MAX_CANDIDATES_TO_VERIFY = 3

    def __init__(self):
        self._trie = PredictionTrie()
        self._patterns = {
            "prefixes": {},    # prefix -> count
            "suffixes": {},    # suffix -> count
            "separators": {},  # separator char -> count
            "case_style": {},  # 'lower'|'upper'|'camel'|'pascal' -> count
        }
        self._learned_values = set()
        self._detected_language = None  # 'en', 'es', or None
        self._lang_scores = {"en": 0, "es": 0}
        self._initialized = False
        self._lock = threading.Lock()

        # CMS detection
        self._detected_cms = None         # detected CMS name or None
        self._cms_boost_applied = False   # whether we already boosted CMS tables

        # Column context: tracks which table we're currently extracting columns for
        self._current_table_context = None
        self._column_predictions_loaded = set()  # tables for which we already loaded columns

        # Value context: tracks which column we're currently extracting values for
        self._current_column_context = None
        self._value_predictions_loaded = set()

        # Request/time tracking for cost analysis
        self.stats_hits = 0             # successful predictions
        self.stats_misses = 0           # failed prediction attempts
        self.stats_chars_saved = 0      # characters skipped thanks to hits
        self.stats_queries_wasted = 0   # queries spent on misses
        self.stats_queries_saved = 0    # queries saved by hits (estimated)
        self.stats_time_wasted = 0.0    # actual seconds spent on missed predictions
        self.stats_time_saved = 0.0     # estimated seconds saved by hits
        self.stats_avg_query_time = 0.0 # running average of real query duration
        self._query_times = []          # recent query durations for averaging

        # Quick schema stats (separate from bisection predictor stats)
        self.stats_quick_tables_confirmed = 0   # tables found via existence queries
        self.stats_quick_tables_missed = 0       # tables checked but not found
        self.stats_quick_columns_confirmed = 0   # columns found via existence queries
        self.stats_quick_columns_missed = 0      # columns checked but not found
        self.stats_prefix_skips = 0              # number of prefix skip verifications
        self.stats_prefix_chars_saved = 0        # total characters skipped via prefix
        self.stats_ordered_trims = 0             # number of charset trims via ordered extraction
        self.stats_ordered_chars_removed = 0     # total chars removed from charsets via ordering
        self.stats_ordered_original_total = 0    # sum of original charset sizes before trimming

        # Precomputed lowercase sets for fast column type detection
        self._hash_col_lower = set(h.lower() for h in self.HASH_COLUMN_NAMES)
        self._ip_col_lower = set(i.lower() for i in self.IP_COLUMN_NAMES)
        self._email_col_lower = set(e.lower() for e in self.EMAIL_COLUMN_NAMES)
        self._url_col_lower = set(u.lower() for u in self.URL_COLUMN_NAMES)

        # Cache for predict() -> get_charset_hint() reuse
        self._last_predict_partial = None
        self._last_predict_candidates = []

        # Ordered extraction: track previous value for min-char optimization
        self._previous_extracted_value = None

        # Auto-detected charset restriction from value patterns (hash, etc.)
        self._auto_detected_charset = None
        self._auto_detected_hash_type = None
        self._auto_detected_hash_prefix = None

        # Learned email domain from previous extractions
        self._learned_email_domain = None

        # Target domain extracted from URL (for email prediction)
        self._target_domain = None

    def initialize(self):
        """
        Load static dictionaries into the trie.
        Called once at first prediction attempt.

        >>> p = SchemaPredictor()
        >>> p.initialize()
        >>> len(p._trie) > 0
        True
        """

        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            # Layer 3: Load common-outputs.txt entries
            self._load_common_outputs()

            # Layer 3b: Load common-tables.txt and common-columns.txt
            self._load_static_file(
                getattr(paths, "COMMON_TABLES", None),
                self.WEIGHT_STATIC_DICT
            )
            self._load_static_file(
                getattr(paths, "COMMON_COLUMNS", None),
                self.WEIGHT_STATIC_DICT
            )

            # Layer 4: Load language dictionaries
            for word in self.ENGLISH_DB_WORDS:
                self._trie.insert(word, self.WEIGHT_LANGUAGE_DICT)

            for word in self.SPANISH_DB_WORDS:
                self._trie.insert(word, self.WEIGHT_LANGUAGE_DICT)

            for word in self.PORTUGUESE_DB_WORDS:
                self._trie.insert(word, self.WEIGHT_LANGUAGE_DICT)

            # Layer 4b: Framework-specific tables (higher weight - known exact names)
            for table in self.FRAMEWORK_TABLES:
                self._trie.insert(table, self.WEIGHT_STATIC_DICT)

            # Layer 4c: Hungarian notation combos (tblUsers, vwOrders, etc.)
            for prefix in self.HUNGARIAN_PREFIXES:
                for word in self.ENGLISH_DB_WORDS:
                    hungarian = prefix + word[0].upper() + word[1:]
                    self._trie.insert(hungarian, self.WEIGHT_LANGUAGE_DICT)

            # Layer 4d: ALL_CAPS versions of English words (CUSTOMER, ORDERS, etc.)
            for word in self.ENGLISH_DB_WORDS:
                self._trie.insert(word.upper(), self.WEIGHT_LANGUAGE_DICT)

            # Layer 4e: ALL_CAPS compound names (CUSTOMER_MASTER, ORDER_HEADER, etc.)
            caps_suffixes = (
                "MASTER", "HEADER", "DETAIL", "DETAILS", "TABLE", "RECORD",
                "RECORDS", "LOG", "LOGS", "CONTROL", "TRANSACTION", "TRANSACTIONS",
                "HISTORY", "STATUS", "TYPE", "TYPES", "CODE", "CODES", "LIST",
                "DATA", "INFO", "CONFIG", "PARAMETER", "PARAMETERS", "ACCOUNT",
            )
            for word in self.ENGLISH_DB_WORDS:
                for suffix in caps_suffixes:
                    compound = "%s_%s" % (word.upper(), suffix)
                    self._trie.insert(compound, self.WEIGHT_LANGUAGE_DICT)

            # Layer 4f: Environment prefix combos (prd_users, stg_orders, dev_products)
            env_prefixes = ("prd_", "stg_", "dev_", "tst_", "qa_", "uat_",
                            "prod_", "test_", "bak_", "tmp_")
            for env in env_prefixes:
                for word in self.ENGLISH_DB_WORDS:
                    self._trie.insert(env + word, self.WEIGHT_LANGUAGE_DICT)
                for word in self.SPANISH_DB_WORDS:
                    self._trie.insert(env + word, self.WEIGHT_LANGUAGE_DICT)

            # Layer 4g: Common database names
            self.load_common_db_names()

            self._initialized = True

            # Learn target domain from URL for email prediction
            self.learn_target_domain()

            debugMsg = "prediction engine initialized with %d entries" % len(self._trie)
            logger.debug(debugMsg)

    def _load_common_outputs(self):
        """
        Load entries from kb.commonOutputs (parsed from common-outputs.txt)
        """

        if kb.get("commonOutputs"):
            for category, values in kb.commonOutputs.items():
                for value in values:
                    self._trie.insert(value, self.WEIGHT_COMMON_OUTPUTS)

    def _load_static_file(self, filepath, weight):
        """
        Load entries from a file (one per line, # comments)
        """

        if not filepath or not os.path.isfile(filepath):
            return

        try:
            with open(filepath, 'r', errors="ignore") as f:
                for line in f:
                    if '#' in line:
                        line = line[:line.index('#')]
                    line = line.strip()
                    if line:
                        self._trie.insert(line, weight)
        except (IOError, OSError):
            pass

    def learn(self, value, context=None):
        """
        Learn from a discovered value (table name, column name, db name, etc).
        Updates the trie, pattern analysis, language detection, and CMS detection.

        Args:
            value: the discovered string
            context: optional category hint ('Tables', 'Columns', 'Databases')

        >>> p = SchemaPredictor()
        >>> p.initialize()
        >>> p.learn("usuario_admin")
        >>> p.learn("usuario_ventas")
        >>> candidates = p.predict("usuario_", length_filter=None)
        >>> any("usuario_admin" in c[0] for c in candidates)
        True
        """

        if not value or value in self._learned_values:
            return

        self._learned_values.add(value)

        # Insert into trie with highest weight
        self._trie.insert(value, self.WEIGHT_SCHEMA_LEARNING)

        # Analyze naming patterns
        self._analyze_patterns(value)

        # Update language detection
        self._update_language_score(value)

        # Generate pattern-derived predictions
        self._generate_pattern_predictions(value)

        # CMS auto-detection: check if this value is a fingerprint table
        if not self._detected_cms:
            self._try_detect_cms(value)

        # Detect dated/sharded table patterns (events_2023_01, partition_0, etc.)
        self.detect_dated_pattern(value)

    # CMS detection by table prefix (faster than fingerprint - triggers on first table)
    CMS_PREFIX_DETECTION = {
        "wp_": "wordpress",
        "jos_": "joomla",
        "mdl_": "moodle",
        "ps_": "prestashop",
        "phpbb_": "phpbb",
        "oc_": "nextcloud",
        "vtiger_": "vtiger",
        "llx_": "dolibarr",
        "glpi_": "glpi",
        "mantis_": "mantis",
    }

    def _try_detect_cms(self, table_name):
        """
        Check if a discovered table name matches a CMS fingerprint or prefix.
        If detected, boost all tables from that CMS to high weight.

        Detection methods (in order):
        1. Exact fingerprint table match (wp_options, jos_extensions, etc.)
        2. Prefix match (wp_*, jos_*, mdl_*, etc.) - triggers on ANY table with CMS prefix
        """

        if self._detected_cms:
            return

        lower_name = table_name.lower()

        # Method 1: Exact fingerprint match
        for cms, fingerprints in self.CMS_FINGERPRINTS.items():
            for fp in fingerprints:
                if lower_name == fp.lower():
                    self._detected_cms = cms
                    self._apply_cms_boost(cms)
                    self._load_db_names_for_cms(cms)

                    infoMsg = "CMS detected: %s (fingerprint: %s)" % (cms, table_name)
                    logger.info(infoMsg)
                    return

        # Method 2: Prefix-based detection (catches wp_comments, wp_links, etc.)
        for prefix, cms in self.CMS_PREFIX_DETECTION.items():
            if lower_name.startswith(prefix):
                self._detected_cms = cms
                self._apply_cms_boost(cms)
                self._load_db_names_for_cms(cms)

                infoMsg = "CMS detected: %s (prefix: %s from table %s)" % (cms, prefix, table_name)
                logger.info(infoMsg)
                return

    def _apply_cms_boost(self, cms):
        """
        Boost all known tables for the detected CMS to WEIGHT_CMS_DETECTED.
        Also load column predictions for all known tables of this CMS.
        """

        if self._cms_boost_applied:
            return

        self._cms_boost_applied = True

        # Find all framework tables that belong to this CMS by prefix pattern
        cms_prefixes = {
            "wordpress": "wp_", "joomla": "jos_", "drupal": None,
            "magento": None, "prestashop": "ps_", "moodle": "mdl_",
            "django": ("auth_", "django_"), "laravel": None,
            "rails": "active_storage_", "phpbb": "phpbb_",
            "nextcloud": "oc_", "suitecrm": None, "vtiger": "vtiger_",
            "dolibarr": "llx_", "glpi": "glpi_", "mantis": "mantis_",
            "mediawiki": None, "ghost": None,
        }

        prefix = cms_prefixes.get(cms)
        boosted = 0

        for table in self.FRAMEWORK_TABLES:
            is_match = False
            if prefix is None:
                # For CMS without unique prefix, boost all framework tables
                # that are in the CMS_FINGERPRINTS list
                if table.lower() in [fp.lower() for fp in self.CMS_FINGERPRINTS.get(cms, [])]:
                    is_match = True
            elif isinstance(prefix, tuple):
                is_match = any(table.lower().startswith(p) for p in prefix)
            else:
                is_match = table.lower().startswith(prefix)

            if is_match:
                self._trie.insert(table, self.WEIGHT_CMS_DETECTED)
                boosted += 1

                # Also load column predictions for this table
                self._load_columns_for_table(table)

        debugMsg = "boosted %d tables for CMS '%s' to weight %d" % (boosted, cms, self.WEIGHT_CMS_DETECTED)
        logger.debug(debugMsg)

    def set_table_context(self, table_name):
        """
        Set the current table context for column prediction.
        Called from inference.py when extracting columns for a specific table.
        """

        if table_name and table_name != self._current_table_context:
            self._current_table_context = table_name
            self._previous_extracted_value = None  # reset ordered extraction
            self._load_columns_for_table(table_name)

    def _load_columns_for_table(self, table_name):
        """
        Load known column names for a table into the trie.
        """

        if table_name in self._column_predictions_loaded:
            return

        self._column_predictions_loaded.add(table_name)

        # Check exact match first
        columns = self.TABLE_COLUMNS.get(table_name)

        # Try lowercase match
        if not columns:
            for tbl, cols in self.TABLE_COLUMNS.items():
                if tbl.lower() == table_name.lower():
                    columns = cols
                    break

        if columns:
            weight = self.WEIGHT_CMS_DETECTED if self._detected_cms else self.WEIGHT_COLUMN_CONTEXT
            for col in columns:
                self._trie.insert(col, weight)

            debugMsg = "loaded %d column predictions for table '%s'" % (len(columns), table_name)
            logger.debug(debugMsg)

    def set_column_context(self, column_name):
        """
        Set the current column context for value prediction.
        Called from inference.py when extracting data values.
        """

        if column_name and column_name != self._current_column_context:
            self._current_column_context = column_name
            self._previous_extracted_value = None  # reset ordered extraction
            self.clear_auto_detected_charset()      # reset auto-detected hash charset
            self._load_values_for_column(column_name)

    def _load_values_for_column(self, column_name):
        """
        Load known value predictions for a column into the trie.
        Also loads URL/path predictions if column name matches URL patterns.
        """

        if column_name in self._value_predictions_loaded:
            return

        self._value_predictions_loaded.add(column_name)

        # Check exact match for standard value predictions
        values = self.COLUMN_VALUE_PREDICTIONS.get(column_name)

        # Try lowercase match
        if not values:
            for col, vals in self.COLUMN_VALUE_PREDICTIONS.items():
                if col.lower() == column_name.lower():
                    values = vals
                    break

        if values:
            # Use COMMON_OUTPUTS weight (60) so contextual values beat generic dict entries (40)
            for val in values:
                self._trie.insert(val, self.WEIGHT_COMMON_OUTPUTS)

            debugMsg = "loaded %d value predictions for column '%s'" % (len(values), column_name)
            logger.debug(debugMsg)

        # URL/path prediction: load if column name looks like a URL field
        col_lower = column_name.lower()
        is_url_column = col_lower in self._url_col_lower

        # Also check partial matches (e.g., "avatar_url" contains "url")
        if not is_url_column:
            for url_col in self._url_col_lower:
                if url_col in col_lower or col_lower in url_col:
                    is_url_column = True
                    break

        if is_url_column:
            loaded = 0

            # Always load generic URL prefixes
            for prefix in self.GENERIC_URL_PREFIXES:
                self._trie.insert(prefix, self.WEIGHT_COMMON_OUTPUTS)
                loaded += 1

            # Load CMS-specific paths ONLY if that CMS is detected
            if self._detected_cms and self._detected_cms in self.CMS_URL_PREFIXES:
                for prefix in self.CMS_URL_PREFIXES[self._detected_cms]:
                    self._trie.insert(prefix, self.WEIGHT_CMS_DETECTED)
                    loaded += 1

            debugMsg = "loaded %d URL/path predictions for column '%s'%s" % (
                loaded, column_name,
                " (CMS: %s)" % self._detected_cms if self._detected_cms else "")
            logger.debug(debugMsg)

        # Hash type prediction: load if column name looks like a password hash field
        is_hash_column = col_lower in self._hash_col_lower
        if not is_hash_column:
            for hash_col in self._hash_col_lower:
                if hash_col in col_lower or col_lower in hash_col:
                    is_hash_column = True
                    break

        if is_hash_column:
            loaded = 0

            # If CMS is detected, load only that CMS's hash types first (highest priority)
            if self._detected_cms and self._detected_cms in self.CMS_HASH_TYPES:
                for hash_type in self.CMS_HASH_TYPES[self._detected_cms]:
                    for prefix in self.HASH_TYPE_PREFIXES.get(hash_type, []):
                        self._trie.insert(prefix, self.WEIGHT_CMS_DETECTED)
                        loaded += 1
            else:
                # No CMS detected: load all common hash prefixes at lower weight
                for hash_type in ("bcrypt", "phpass", "md5_crypt", "sha256_crypt", "sha512_crypt", "argon2", "mysql_native"):
                    for prefix in self.HASH_TYPE_PREFIXES.get(hash_type, []):
                        self._trie.insert(prefix, self.WEIGHT_COMMON_OUTPUTS)
                        loaded += 1

            debugMsg = "loaded %d hash prefix predictions for column '%s'%s" % (
                loaded, column_name,
                " (CMS: %s)" % self._detected_cms if self._detected_cms else "")
            logger.debug(debugMsg)

        # Email prediction: load if column name looks like an email field
        is_email_column = col_lower in self._email_col_lower
        if not is_email_column:
            for email_col in self._email_col_lower:
                if email_col in col_lower or col_lower in email_col:
                    is_email_column = True
                    break

        if is_email_column:
            # Load email domains as "@domain.com" so they match after the @ is extracted
            loaded = 0
            for domain in self.EMAIL_DOMAINS:
                self._trie.insert("@%s" % domain, self.WEIGHT_COMMON_OUTPUTS)
                loaded += 1

            debugMsg = "loaded %d email domain predictions for column '%s'" % (loaded, column_name)
            logger.debug(debugMsg)

        # IP address prediction: load if column name looks like an IP field
        is_ip_column = col_lower in self._ip_col_lower
        if not is_ip_column:
            for ip_col in self._ip_col_lower:
                if ip_col in col_lower or col_lower in ip_col:
                    is_ip_column = True
                    break

        if is_ip_column:
            loaded = 0
            for prefix in self.COMMON_IP_PREFIXES:
                self._trie.insert(prefix, self.WEIGHT_COMMON_OUTPUTS)
                loaded += 1

            debugMsg = "loaded %d IP prefix predictions for column '%s'" % (loaded, column_name)
            logger.debug(debugMsg)

    def detect_cms_from_http(self, headers=None, cookies=None, body=None):
        """
        Passive CMS detection from HTTP response headers, cookies, and body content.
        Called early in the scan before any data extraction begins.

        Args:
            headers: dict or string of HTTP response headers
            cookies: string of cookie values
            body: string of HTTP response body
        """

        if self._detected_cms:
            return self._detected_cms

        headers_str = str(headers).lower() if headers else ""
        cookies_str = str(cookies).lower() if cookies else ""
        body_str = str(body).lower() if body else ""

        best_cms = None
        best_score = 0

        for cms, fingerprints in self.HTTP_FINGERPRINTS.items():
            score = 0

            for pattern in fingerprints.get("headers", []):
                if pattern.lower() in headers_str:
                    score += 3  # headers are strong signals

            for pattern in fingerprints.get("cookies", []):
                if pattern.lower() in cookies_str:
                    score += 3  # cookies are strong signals

            for pattern in fingerprints.get("body", []):
                if pattern.lower() in body_str:
                    score += 1  # body matches are weaker (could be false positives)

            if score > best_score:
                best_score = score
                best_cms = cms

        # Require at least 2 points to be confident
        if best_cms and best_score >= 2:
            self._detected_cms = best_cms

            if self._initialized:
                self._apply_cms_boost(best_cms)
                self._load_db_names_for_cms(best_cms)

            infoMsg = "CMS detected via HTTP fingerprint: %s (confidence: %d)" % (best_cms, best_score)
            logger.info(infoMsg)

        return self._detected_cms

    def _load_db_names_for_cms(self, cms):
        """
        Load common database names for the detected CMS into the trie.
        """

        db_names = self.CMS_DATABASE_NAMES.get(cms, [])
        for name in db_names:
            self._trie.insert(name, self.WEIGHT_CMS_DETECTED)

        debugMsg = "loaded %d database name predictions for CMS '%s'" % (len(db_names), cms)
        logger.debug(debugMsg)

    def load_common_db_names(self):
        """
        Load generic and CMS database names into the trie (called during initialize).
        """

        for name in self.COMMON_DATABASE_NAMES:
            self._trie.insert(name, self.WEIGHT_STATIC_DICT)

        # Also load all CMS database names at lower weight
        # (will be boosted to WEIGHT_CMS_DETECTED when CMS is detected)
        for cms, names in self.CMS_DATABASE_NAMES.items():
            for name in names:
                self._trie.insert(name, self.WEIGHT_LANGUAGE_DICT)

    def detect_dated_pattern(self, value):
        """
        Detect dated/sharded table patterns and generate predictions.
        If we see events_2023_01, generate events_2023_02 through events_2024_12.

        Patterns detected:
        - base_YYYY_MM (events_2023_01)
        - base_YYYY (logs_2023)
        - base_N (partition_0, partition_1)

        >>> p = SchemaPredictor()
        >>> p.initialize()
        >>> p.detect_dated_pattern("events_2023_01")
        >>> candidates = p.predict("events_2023_0", max_results=5)
        >>> any("events_2023_02" in c[0] for c in candidates)
        True
        """

        import re

        # Pattern: base_YYYY_MM
        match = re.match(r'^(.+?)(\d{4})_(\d{2})$', value)
        if match:
            base, year, month = match.group(1), int(match.group(2)), int(match.group(3))
            generated = 0
            for y in range(year - 1, year + 3):
                for m in range(1, 13):
                    candidate = "%s%d_%02d" % (base, y, m)
                    if candidate != value:
                        self._trie.insert(candidate, self.WEIGHT_PATTERN_DERIVED)
                        generated += 1
            if generated:
                debugMsg = "dated pattern detected: %sYYYY_MM, generated %d predictions" % (base, generated)
                logger.debug(debugMsg)
            return

        # Pattern: base_YYYY
        match = re.match(r'^(.+?)(\d{4})$', value)
        if match:
            base, year = match.group(1), int(match.group(2))
            generated = 0
            for y in range(year - 2, year + 4):
                candidate = "%s%d" % (base, y)
                if candidate != value:
                    self._trie.insert(candidate, self.WEIGHT_PATTERN_DERIVED)
                    generated += 1
            if generated:
                debugMsg = "dated pattern detected: %sYYYY, generated %d predictions" % (base, generated)
                logger.debug(debugMsg)
            return

        # Pattern: base_N (partition_0, partition_1, etc.)
        match = re.match(r'^(.+?)(\d+)$', value)
        if match:
            base, num = match.group(1), int(match.group(2))
            # Only if it looks like a partition/shard (number < 100)
            if num < 100 and len(match.group(2)) <= 2:
                generated = 0
                for n in range(0, max(num + 10, 20)):
                    candidate = "%s%d" % (base, n)
                    if candidate != value:
                        self._trie.insert(candidate, self.WEIGHT_PATTERN_DERIVED)
                        generated += 1
                if generated:
                    debugMsg = "partition pattern detected: %sN, generated %d predictions" % (base, generated)
                    logger.debug(debugMsg)

    def build_length_combined_query(self, expression, candidate_value):
        """
        Build a combined LENGTH + equality query for one-shot verification.
        Instead of: query1: LENGTH(x)=8, query2: x='wp_users'
        Does: LENGTH(x)=8 AND x='wp_users' in a single query.

        Returns the combined condition string, or None if not applicable.

        This is used by inference.py to skip the separate LENGTH extraction
        when we have a high-confidence candidate.
        """

        if not candidate_value:
            return None

        return "LENGTH(%s)=%d AND (%s)='%s'" % (
            expression, len(candidate_value), expression, candidate_value
        )

    def get_quick_schema_tables(self):
        """
        Returns the list of tables to verify via quick schema dump.
        Only available when CMS is detected. Each table gets verified with
        a single equality query instead of character-by-character extraction.

        Returns:
            List of table name strings if CMS is detected, empty list otherwise.

        Usage from sqlmap enumeration:
            tables = predictor.get_quick_schema_tables()
            for table in tables:
                # verify: SELECT COUNT(*) FROM information_schema.tables
                #         WHERE table_schema='dbname' AND table_name='table'
                if verify_table_exists(table):
                    confirmed_tables.append(table)
        """

        if not self._detected_cms:
            return []

        tables = self.QUICK_SCHEMA_TABLES.get(self._detected_cms, [])

        if tables:
            infoMsg = "quick schema: %d candidate tables for CMS '%s' ready for verification" % (
                len(tables), self._detected_cms)
            logger.info(infoMsg)

        return list(tables)

    def get_quick_schema_stats(self, verified_count, total_candidates):
        """
        Generate stats for quick schema dump.
        """

        if total_candidates == 0:
            return None

        hit_rate = 100.0 * verified_count / total_candidates
        queries_used = total_candidates  # one query per candidate
        # Normal extraction would have been: verified_count tables * avg 10 chars * 8 queries
        queries_normal = verified_count * 10 * 8

        lines = []
        lines.append("quick schema: verified %d/%d tables (%.0f%% hit rate)" % (
            verified_count, total_candidates, hit_rate))
        lines.append("quick schema: used %d queries instead of ~%d (saved ~%d queries)" % (
            queries_used, queries_normal, queries_normal - queries_used))

        return lines

    def _analyze_patterns(self, value):
        """
        Extract naming patterns from a value, including PascalCase prefixes

        >>> p = SchemaPredictor()
        >>> p._analyze_patterns("tbl_users")
        >>> p._patterns["prefixes"]["tbl_"]
        1
        >>> p._analyze_patterns("tbl_orders")
        >>> p._patterns["prefixes"]["tbl_"]
        2
        >>> p._analyze_patterns("SEGUsuario")
        >>> p._patterns["prefixes"]["SEG"]
        1
        >>> p._analyze_patterns("SEGAccesos")
        >>> p._patterns["prefixes"]["SEG"]
        2
        """

        # Detect separators
        for sep in ('_', '-', '.'):
            if sep in value:
                self._patterns["separators"][sep] = self._patterns["separators"].get(sep, 0) + 1

        # Detect case style
        if value == value.lower():
            style = "lower"
        elif value == value.upper():
            style = "upper"
        elif value[0].isupper() and '_' not in value and '-' not in value:
            if any(c.islower() for c in value[1:]) and any(c.isupper() for c in value[1:]):
                style = "camel"
            else:
                style = "pascal"
        else:
            style = "lower"

        self._patterns["case_style"][style] = self._patterns["case_style"].get(style, 0) + 1

        # Detect common prefixes with separators (e.g., tbl_, wp_, t_)
        for sep in ('_', '-'):
            if sep in value:
                parts = value.split(sep)
                if len(parts) >= 2:
                    prefix = parts[0] + sep
                    if len(prefix) <= 5:  # short prefixes only
                        self._patterns["prefixes"][prefix] = self._patterns["prefixes"].get(prefix, 0) + 1

                    # Also track suffixes
                    suffix = sep + parts[-1]
                    if len(suffix) <= 8:
                        self._patterns["suffixes"][suffix] = self._patterns["suffixes"].get(suffix, 0) + 1

        # Detect PascalCase prefixes without separators (e.g., SEG in SEGUsuario)
        # Pattern: consecutive uppercase letters where the LAST uppercase before
        # a lowercase transition starts the next word.
        # Examples: SEGAccesos -> SEG + Accesos, SEGUsuario -> SEG + Usuario
        #           HTMLParser -> HTML + Parser (last upper before lower = next word)
        if len(value) >= 3 and '_' not in value and '-' not in value:
            upper_run = 0
            for ch in value:
                if ch.isupper():
                    upper_run += 1
                else:
                    break

            # If we have 3+ uppercase chars and the char after the run is lowercase,
            # the actual prefix is upper_run - 1 (last uppercase starts next word)
            # E.g., "SEGA..." -> upper_run=4, but prefix is "SEG" (3), "A" starts "Accesos"
            # But if ALL chars are uppercase, it's just an all-caps name, skip it
            if upper_run >= 3 and upper_run < len(value):
                # Check if char at upper_run position is lowercase
                if value[upper_run].islower():
                    # The last uppercase char is the start of the next word
                    pascal_prefix = value[:upper_run - 1]
                else:
                    # Next char is also uppercase or non-alpha, take full run
                    pascal_prefix = value[:upper_run]

                if 2 <= len(pascal_prefix) <= 6:
                    self._patterns["prefixes"][pascal_prefix] = self._patterns["prefixes"].get(pascal_prefix, 0) + 1

        # Detect Hungarian notation prefixes (tblCustomer, vwOrders, etc.)
        # Pattern: known short lowercase prefix immediately followed by uppercase
        if len(value) >= 4 and '_' not in value and '-' not in value:
            for hp in self.HUNGARIAN_PREFIXES:
                if value.startswith(hp) and len(value) > len(hp) and value[len(hp)].isupper():
                    self._patterns["prefixes"][hp] = self._patterns["prefixes"].get(hp, 0) + 1
                    break

        # Detect environment prefixes (prd_, stg_, dev_, bak_, tmp_)
        if '_' in value:
            first_part = value.split('_')[0].lower()
            if first_part in ('prd', 'stg', 'dev', 'bak', 'tmp', 'tst', 'qa', 'uat', 'prod', 'test'):
                env_prefix = first_part + '_'
                self._patterns["prefixes"][env_prefix] = self._patterns["prefixes"].get(env_prefix, 0) + 1

    def _update_language_score(self, value):
        """
        Heuristic language detection based on discovered names.
        Handles snake_case, PascalCase, and plain words.

        >>> p = SchemaPredictor()
        >>> p._update_language_score("usuarios")
        >>> p._lang_scores["es"] > p._lang_scores["en"]
        True
        >>> p2 = SchemaPredictor()
        >>> p2._update_language_score("SEGUsuario")
        >>> p2._lang_scores["es"] > p2._lang_scores["en"]
        True
        """

        # Split by separators first
        normalized = value.replace('_', ' ').replace('-', ' ')

        # Also split PascalCase: "SEGUsuarioFuncion" -> "SEG Usuario Funcion"
        pascal_split = []
        current = []
        for ch in normalized:
            if ch == ' ':
                if current:
                    pascal_split.append(''.join(current))
                    current = []
                pascal_split.append(' ')
            elif ch.isupper() and current and not current[-1].isupper():
                pascal_split.append(''.join(current))
                current = [ch]
            elif ch.isupper() and current and current[-1].isupper():
                # Check if next would be lowercase (end of acronym)
                current.append(ch)
            else:
                current.append(ch)
        if current:
            pascal_split.append(''.join(current))

        tokens = [t.lower() for t in pascal_split if t.strip() and len(t) > 2]

        en_words = set(self.ENGLISH_DB_WORDS)
        es_words = set(self.SPANISH_DB_WORDS)
        pt_words = set(self.PORTUGUESE_DB_WORDS)

        for token in tokens:
            if token in en_words:
                self._lang_scores["en"] += 1
            if token in es_words:
                self._lang_scores["es"] += 1
            if token in pt_words:
                self._lang_scores["pt"] = self._lang_scores.get("pt", 0) + 1

    def _generate_pattern_predictions(self, value):
        """
        Generate new predictions by combining known prefixes/suffixes
        with dictionary words.

        Handles separator-based (tbl_users), PascalCase (SEGUsuario),
        Hungarian (tblCustomer), and ALL_CAPS (CUSTOMER_MASTER) patterns.

        >>> p = SchemaPredictor()
        >>> p.initialize()
        >>> p.learn("wp_users")
        >>> p.learn("wp_posts")
        >>> candidates = p.predict("wp_c", length_filter=None)
        >>> len(candidates) > 0
        True
        >>> p2 = SchemaPredictor()
        >>> p2.initialize()
        >>> p2.learn("SEGUsuario")
        >>> p2.learn("SEGAccesos")
        >>> candidates = p2.predict("SEGMe", length_filter=None)
        >>> len(candidates) > 0
        True
        """

        # Only generate after we've seen a prefix at least twice
        frequent_prefixes = [
            pfx for pfx, count in self._patterns["prefixes"].items()
            if count >= 2
        ]

        dominant_lang = self._get_dominant_language()

        for prefix in frequent_prefixes:
            # Determine prefix type
            is_pascal_prefix = prefix == prefix.upper() and not prefix.endswith(('_', '-')) and len(prefix) >= 2
            is_hungarian = prefix.lower() in [hp.lower() for hp in self.HUNGARIAN_PREFIXES]
            has_separator = prefix.endswith(('_', '-'))

            # Get the appropriate word list based on detected language
            all_words = list(self.ENGLISH_DB_WORDS)
            if dominant_lang == "es":
                all_words = list(self.SPANISH_DB_WORDS) + all_words
            elif dominant_lang == "pt":
                all_words = list(self.PORTUGUESE_DB_WORDS) + all_words
            else:
                all_words = all_words + list(self.SPANISH_DB_WORDS)

            for word in all_words:
                if is_pascal_prefix:
                    candidate = prefix + word[0].upper() + word[1:]
                elif is_hungarian:
                    candidate = prefix + word[0].upper() + word[1:]
                elif has_separator:
                    candidate = prefix + word
                else:
                    candidate = prefix + word

                if candidate not in self._learned_values:
                    if has_separator:
                        candidate = self._apply_case_style(candidate)
                    self._trie.insert(candidate, self.WEIGHT_PATTERN_DERIVED)

            # For separator prefixes, also generate ALL_CAPS versions
            if has_separator:
                for word in self.ENGLISH_DB_WORDS:
                    caps_candidate = (prefix + word).upper()
                    if caps_candidate not in self._learned_values:
                        self._trie.insert(caps_candidate, self.WEIGHT_PATTERN_DERIVED)

    def _get_dominant_language(self):
        """
        Returns the dominant language based on accumulated scores

        >>> p = SchemaPredictor()
        >>> p._lang_scores = {"en": 5, "es": 10}
        >>> p._get_dominant_language()
        'es'
        """

        if self._lang_scores["es"] > self._lang_scores["en"]:
            return "es"
        return "en"

    def _apply_case_style(self, value):
        """
        Apply the dominant case style from patterns

        >>> p = SchemaPredictor()
        >>> p._patterns["case_style"] = {"upper": 5, "lower": 1}
        >>> p._apply_case_style("test_value")
        'TEST_VALUE'
        """

        if not self._patterns["case_style"]:
            return value

        dominant = max(self._patterns["case_style"], key=self._patterns["case_style"].get)

        if dominant == "upper":
            return value.upper()
        elif dominant == "lower":
            return value.lower()

        return value

    def predict(self, partial_value, length_filter=None, max_results=None):
        """
        Main prediction method. Returns list of (candidate, weight) tuples.
        Searches with case normalization so CUSTOMER_MASTER matches customer_master.

        Also caches the last search results for get_charset_hint() reuse.

        Args:
            partial_value: characters retrieved so far
            length_filter: if known, filter candidates by exact length
            max_results: max number of results to return

        Returns:
            List of (candidate_string, weight) sorted by weight descending

        >>> p = SchemaPredictor()
        >>> p.initialize()
        >>> results = p.predict("info")
        >>> len(results) > 0
        True
        >>> results2 = p.predict("CUST")
        >>> any("CUSTOMER" in c[0].upper() for c in results2)
        True
        """

        if not self._initialized:
            self.initialize()

        if not partial_value or len(partial_value) < self.MIN_PREFIX_LENGTH:
            self._last_predict_candidates = []
            return []

        if max_results is None:
            max_results = self.MAX_CANDIDATES_TO_VERIFY

        # The trie stores keys as lowercase internally, so search_prefix
        # already matches case-insensitively. No need for a second search.
        candidates = self._trie.search_prefix(
            partial_value,
            max_results=max_results * 5,
            length_filter=length_filter
        )

        # If input is uppercase, re-case candidates to match
        is_upper = partial_value == partial_value.upper() and not partial_value == partial_value.lower()
        if is_upper:
            candidates = [(val.upper(), weight) for val, weight in candidates]

        # Deduplicate by lowercase key, keeping highest weight
        seen = {}
        for val, weight in candidates:
            key = val.lower()
            if key not in seen or weight > seen[key][1]:
                seen[key] = (val, weight)

        candidates = sorted(seen.values(), key=lambda x: -x[1])

        # Filter out candidates that are identical to the partial value
        candidates = [c for c in candidates if c[0].lower() != partial_value.lower()]

        result = candidates[:max_results]

        # Cache for get_charset_hint() reuse
        self._last_predict_partial = partial_value
        self._last_predict_candidates = candidates

        return result

    def detect_hash_from_value(self, value):
        """
        Auto-detect if a value is a hash based on its pattern.
        If detected, sets _auto_detected_charset for subsequent extractions
        and _auto_detected_hash_prefix for prefix skip.
        Called after the first value in a column is fully extracted.

        Returns:
            str: hash type name if detected, None otherwise
        """

        if not value or len(value) < 16:
            return None

        # Already detected for this column
        if self._auto_detected_hash_type:
            return self._auto_detected_hash_type

        # Check known hash prefixes
        hash_patterns = {
            "phpass": (["$P$", "$H$"], 34),
            "bcrypt": (["$2y$10$", "$2y$12$", "$2a$10$", "$2a$12$", "$2b$10$"], 60),
            "md5_crypt": (["$1$"], None),
            "sha256_crypt": (["$5$"], None),
            "sha512_crypt": (["$6$"], None),
            "mysql_native": (["*"], 41),
        }

        for hash_type, (prefixes, expected_len) in hash_patterns.items():
            for prefix in prefixes:
                if value.startswith(prefix):
                    if hash_type in self.HASH_STRUCTURES:
                        self._auto_detected_charset = sorted(set(ord(c) for c in self.HASH_STRUCTURES[hash_type]["charset"]))
                        self._auto_detected_hash_type = hash_type
                        self._auto_detected_hash_prefix = prefix

                        infoMsg = "auto-detected hash type: %s (prefix '%s', charset: %d chars)" % (
                            hash_type, prefix, len(self._auto_detected_charset))
                        logger.info(infoMsg)
                        return hash_type

        # Check if it's pure hex (MD5, SHA1, SHA256)
        hex_lengths = {32: "md5_hex", 40: "sha1_hex", 64: "sha256_hex"}
        if len(value) in hex_lengths and all(c in "0123456789abcdefABCDEF" for c in value):
            hash_type = hex_lengths[len(value)]
            if hash_type in self.HASH_STRUCTURES:
                self._auto_detected_charset = sorted(set(ord(c) for c in self.HASH_STRUCTURES[hash_type]["charset"]))
                self._auto_detected_hash_type = hash_type
                self._auto_detected_hash_prefix = None  # no fixed prefix for hex hashes

                infoMsg = "auto-detected hash type: %s (%d hex chars, charset: %d chars)" % (
                    hash_type, len(value), len(self._auto_detected_charset))
                logger.info(infoMsg)
                return hash_type

        # Check if it looks like a generic hash (high entropy, limited charset)
        if len(value) >= 20:
            unique_chars = set(value)
            hash_chars = set("0123456789abcdefABCDEF$./+*=")
            if unique_chars.issubset(hash_chars):
                generic_charset = "0123456789abcdefABCDEF$./+*="
                self._auto_detected_charset = sorted(set(ord(c) for c in generic_charset))
                self._auto_detected_hash_type = "generic_hash"
                self._auto_detected_hash_prefix = None

                infoMsg = "auto-detected hash pattern (charset: %d chars)" % len(self._auto_detected_charset)
                logger.info(infoMsg)
                return "generic_hash"

        return None

    def clear_auto_detected_charset(self):
        """Reset auto-detected charset when switching columns."""
        self._auto_detected_charset = None
        self._auto_detected_hash_type = None
        self._auto_detected_hash_prefix = None
        self._learned_email_domain = None

    def learn_target_domain(self):
        """
        Extract the domain from conf.url and store it for email domain prediction.
        Only stores if it's a real domain (not an IP address).
        Called once during initialization.
        """

        try:
            url = conf.url
            if not url:
                return

            # Extract hostname from URL
            from thirdparty.six.moves.urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.hostname

            if not hostname:
                return

            # Skip if it's an IP address
            import re
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                return
            if hostname == 'localhost':
                return

            # Remove www. prefix if present
            if hostname.startswith('www.'):
                hostname = hostname[4:]

            self._target_domain = hostname

            debugMsg = "learned target domain for email prediction: %s" % hostname
            logger.debug(debugMsg)

        except Exception:
            pass

    def get_hash_prefix_to_skip(self):
        """
        Returns the fixed prefix of the auto-detected hash type for prefix skip.
        Uses the exact prefix found in the first extracted value.

        Returns:
            str: prefix to skip (e.g., '$P$', '$2y$10$', '*'), or None
        """

        if not self._auto_detected_hash_type or not self._auto_detected_hash_prefix:
            return None

        return self._auto_detected_hash_prefix

    def get_column_charset_restriction(self, column_name):
        """
        Returns a restricted charset (list of ord values) for columns with known
        character sets. Uses precomputed lowercase sets for fast lookup.

        Returns:
            List of ord values if restriction applies, None otherwise.
        """

        if not column_name:
            return None

        col_lower = column_name.lower()

        # Check if this is a hash column (fast set lookup + substring check)
        is_hash = col_lower in self._hash_col_lower
        if not is_hash:
            for h in self._hash_col_lower:
                if h in col_lower or col_lower in h:
                    is_hash = True
                    break

        if is_hash:
            hash_struct_name = None
            if self._detected_cms:
                hash_struct_name = self.CMS_HASH_STRUCTURE.get(self._detected_cms)

            if hash_struct_name and hash_struct_name in self.HASH_STRUCTURES:
                struct = self.HASH_STRUCTURES[hash_struct_name]
                return sorted(set(ord(c) for c in struct["charset"]))

            # Without CMS, do NOT apply generic hash charset by column name alone
            # (generic charset is too restrictive for unknown hash types)
            # Wait for auto-detection from the first extracted value instead

        # Check if this is an IP column (fast set lookup + substring check)
        is_ip = col_lower in self._ip_col_lower
        if not is_ip:
            for i in self._ip_col_lower:
                if i in col_lower or col_lower in i:
                    is_ip = True
                    break

        if is_ip:
            return sorted(set(ord(c) for c in self.IP_CHARSET))

        # Check if this is an email column
        is_email = col_lower in self._email_col_lower
        if not is_email:
            for e in self._email_col_lower:
                if e in col_lower or col_lower in e:
                    is_email = True
                    break

        if is_email:
            email_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.@_+-"
            return sorted(set(ord(c) for c in email_chars))

        # Fallback: auto-detected charset from first extracted value
        if self._auto_detected_charset:
            return self._auto_detected_charset

        return None

    def get_hash_expected_length(self):
        """
        Returns the expected hash length based on detected CMS.
        Used to validate LENGTH() results and for pre-extraction prediction.

        Returns:
            int or None
        """

        if not self._detected_cms:
            return None

        hash_struct_name = self.CMS_HASH_STRUCTURE.get(self._detected_cms)
        if hash_struct_name and hash_struct_name in self.HASH_STRUCTURES:
            return self.HASH_STRUCTURES[hash_struct_name]["length"]

        return None

    def learn_ip_prefix(self, ip_value):
        """
        Learn the IP prefix from a discovered IP address and predict
        that other IPs in the same dataset share the same prefix.

        Called after extracting an IP value. If the IP is 192.168.1.105,
        adds 192.168.1. as a high-weight prediction for future IPs.
        """

        if not ip_value or '.' not in ip_value:
            return

        # Extract the first 3 octets as prefix (e.g., "192.168.1.")
        parts = ip_value.split('.')
        if len(parts) >= 3:
            learned_prefix = '.'.join(parts[:3]) + '.'
            self._trie.insert(learned_prefix, self.WEIGHT_SCHEMA_LEARNING)

            debugMsg = "learned IP prefix '%s' from value '%s'" % (learned_prefix, ip_value)
            logger.debug(debugMsg)

    def get_min_char_for_position(self, partial_value, position):
        """
        Returns the minimum possible character (as ord value) for the given position,
        based on the alphabetical ordering of values from information_schema.

        MySQL uses case-insensitive collation, so 'COMCliente' < 'COMDetallePedido'
        because 'C' < 'D' case-insensitively. We return the UPPERCASE version of the
        min char to safely cover both cases (since uppercase has lower ASCII values).

        Args:
            partial_value: characters extracted so far for current value
            position: 1-indexed character position being extracted

        Returns:
            int (ord value) of minimum possible char, or None if no constraint
        """

        prev = self._previous_extracted_value
        if not prev:
            return None

        # Position is 1-indexed in sqlmap
        idx = position - 1  # convert to 0-indexed

        # Check if we're still in the "matching prefix" zone
        # If any previous character in the partial already differs from prev,
        # then there's no constraint (current value is already > previous)
        for i in range(min(len(partial_value), len(prev))):
            if i >= idx:
                break
            if i < len(partial_value):
                if partial_value[i].lower() > prev[i].lower():
                    return None
                elif partial_value[i].lower() < prev[i].lower():
                    return None

        # If we reach here, all chars up to current position match the previous value
        # Return the UPPERCASE version of the char — this is the lowest ASCII value
        # that's valid, and covers both 'D' (68) and 'd' (100) when min is 'd'
        if idx < len(prev):
            ch = prev[idx]
            if ch.isalpha():
                return ord(ch.upper())
            return ord(ch)

        return None

    def set_previous_value(self, value):
        """Record the last fully extracted value for ordered extraction optimization."""
        if value:
            self._previous_extracted_value = value

    def get_charset_hint(self, partial_value):
        """
        Returns a prioritized charset based on what characters are most likely
        at the next position, given the partial value so far.

        Reuses cached results from the last predict() call when possible,
        avoiding a redundant trie traversal.

        >>> p = SchemaPredictor()
        >>> p.initialize()
        >>> charset = p.get_charset_hint("user")
        >>> len(charset) > 0
        True
        """

        if not self._initialized:
            self.initialize()

        if not partial_value:
            return []

        # Reuse candidates from last predict() call if prefix matches
        if (hasattr(self, '_last_predict_partial')
                and self._last_predict_partial == partial_value
                and hasattr(self, '_last_predict_candidates')
                and self._last_predict_candidates):
            candidates = self._last_predict_candidates
        else:
            candidates = self._trie.search_prefix(partial_value, max_results=50)

        if not candidates:
            return []

        # Collect the next character from each candidate, weighted
        char_weights = {}
        plen = len(partial_value)
        for candidate_value, weight in candidates:
            if len(candidate_value) > plen:
                next_char = candidate_value[plen]
                char_weights[next_char] = char_weights.get(next_char, 0) + weight

        # Sort by weight and return as list of ord values
        sorted_chars = sorted(char_weights.items(), key=lambda x: -x[1])
        return [ord(c) for c, _ in sorted_chars]

    def record_query_time(self, duration):
        """
        Record the actual duration of a query (hit or miss) for accurate timing stats.
        Called from inference.py after each prediction query with threadData.lastQueryDuration.
        """

        self._query_times.append(duration)
        # Keep last 50 for rolling average
        if len(self._query_times) > 50:
            self._query_times = self._query_times[-50:]
        self.stats_avg_query_time = sum(self._query_times) / len(self._query_times)

    def record_hit(self, predicted_value, prefix_len, query_duration=None):
        """
        Record a successful prediction.
        Args:
            predicted_value: the full value that was predicted
            prefix_len: how many chars were extracted before the hit
            query_duration: actual time the verification query took (seconds)
        """

        chars_saved = len(predicted_value) - prefix_len
        queries_saved = chars_saved * 7  # ~7 queries per char in bisection

        self.stats_hits += 1
        self.stats_chars_saved += chars_saved
        self.stats_queries_saved += queries_saved

        if query_duration is not None:
            self.record_query_time(query_duration)

        # Estimate time saved using real avg query time or conf.timeSec
        avg_time = self.stats_avg_query_time if self.stats_avg_query_time > 0 else (conf.get("timeSec") or 5)
        self.stats_time_saved += chars_saved * 7 * avg_time

    def record_miss(self, query_duration=None):
        """
        Record a failed prediction attempt (1 wasted query).
        Args:
            query_duration: actual time the verification query took (seconds)
        """

        self.stats_misses += 1
        self.stats_queries_wasted += 1

        if query_duration is not None:
            self.record_query_time(query_duration)
            self.stats_time_wasted += query_duration
        else:
            self.stats_time_wasted += self.stats_avg_query_time if self.stats_avg_query_time > 0 else (conf.get("timeSec") or 5)

    def get_efficiency_report(self):
        """
        Returns a human-readable efficiency report.
        Shows queries saved by each optimization layer.
        """

        total_attempts = self.stats_hits + self.stats_misses
        has_quick_schema = (self.stats_quick_tables_confirmed + self.stats_quick_columns_confirmed) > 0
        has_prefix_skip = self.stats_prefix_skips > 0
        has_ordered = self.stats_ordered_trims > 0

        if total_attempts == 0 and not has_quick_schema and not has_prefix_skip and not has_ordered:
            return None

        queries_per_char = 8
        avg_table_len = 12
        avg_col_len = 8
        total_queries_saved = 0

        lines = []
        if self._detected_cms:
            lines.append("predictor CMS detected: %s" % self._detected_cms)

        # ─── Quick Schema ───
        if has_quick_schema:
            quick_table_saved = self.stats_quick_tables_confirmed * avg_table_len * queries_per_char
            quick_col_saved = self.stats_quick_columns_confirmed * avg_col_len * queries_per_char
            quick_cost = (self.stats_quick_tables_confirmed + self.stats_quick_tables_missed +
                          self.stats_quick_columns_confirmed + self.stats_quick_columns_missed)
            net_quick = quick_table_saved + quick_col_saved - quick_cost
            total_queries_saved += net_quick

            lines.append("quick schema - tables: %d, columns: %d, queries saved: %+d" % (
                self.stats_quick_tables_confirmed, self.stats_quick_columns_confirmed, net_quick))

        # ─── Prefix Skip ───
        if has_prefix_skip:
            prefix_saved = self.stats_prefix_chars_saved * queries_per_char
            prefix_cost = self.stats_prefix_skips
            net_prefix = prefix_saved - prefix_cost
            total_queries_saved += net_prefix

            lines.append("prefix skip - skips: %d, chars saved: %d, queries saved: %+d" % (
                self.stats_prefix_skips, self.stats_prefix_chars_saved, net_prefix))

        # ─── Ordered Extraction ───
        if has_ordered:
            import math
            ordered_queries_saved = 0
            if self.stats_ordered_trims > 0 and self.stats_ordered_original_total > 0:
                avg_original = self.stats_ordered_original_total / self.stats_ordered_trims
                avg_trimmed = avg_original - (self.stats_ordered_chars_removed / self.stats_ordered_trims)
                if avg_trimmed > 1 and avg_original > avg_trimmed:
                    saved_per_trim = math.log2(avg_original) - math.log2(avg_trimmed)
                    ordered_queries_saved = int(saved_per_trim * self.stats_ordered_trims)
            total_queries_saved += ordered_queries_saved

            lines.append("ordered charset - trims: %d, avg charset: %d -> %d, queries saved: ~%d" % (
                self.stats_ordered_trims,
                int(self.stats_ordered_original_total / self.stats_ordered_trims) if self.stats_ordered_trims > 0 else 0,
                int((self.stats_ordered_original_total - self.stats_ordered_chars_removed) / self.stats_ordered_trims) if self.stats_ordered_trims > 0 else 0,
                ordered_queries_saved))

        # ─── Bisection Predictor ───
        if total_attempts > 0:
            net_queries = self.stats_queries_saved - self.stats_queries_wasted
            hit_rate = (100.0 * self.stats_hits / total_attempts) if total_attempts > 0 else 0
            total_queries_saved += net_queries

            lines.append("predictor - hits: %d, misses: %d, hit rate: %.0f%%, queries saved: %+d" % (
                self.stats_hits, self.stats_misses, hit_rate, net_queries))

        # ─── Total ───
        if total_queries_saved > 0:
            lines.append("TOTAL: %+d queries saved" % total_queries_saved)
        elif total_queries_saved < 0:
            lines.append("TOTAL: %d queries wasted (consider --no-predict)" % total_queries_saved)
        else:
            lines.append("TOTAL: neutral (no net effect)")

        return lines

    def get_stats(self):
        """
        Returns statistics about the predictor state (for debugging)

        >>> p = SchemaPredictor()
        >>> stats = p.get_stats()
        >>> "trie_size" in stats
        True
        """

        return {
            "trie_size": len(self._trie),
            "learned_values": len(self._learned_values),
            "prefixes": dict(self._patterns["prefixes"]),
            "suffixes": dict(self._patterns["suffixes"]),
            "separators": dict(self._patterns["separators"]),
            "case_style": dict(self._patterns["case_style"]),
            "lang_scores": dict(self._lang_scores),
            "dominant_language": self._get_dominant_language(),
        }

    def serialize_learned(self):
        """
        Serialize learned values for persistence in hashDB.
        Returns a comma-separated string of all learned values.

        >>> p = SchemaPredictor()
        >>> p.initialize()
        >>> p.learn("users")
        >>> p.learn("orders")
        >>> data = p.serialize_learned()
        >>> "users" in data and "orders" in data
        True
        """

        if not self._learned_values:
            return ""

        return "\n".join(sorted(self._learned_values))

    def restore_learned(self, data):
        """
        Restore learned values from a serialized string (from hashDB).
        Re-learns each value to rebuild the trie, patterns, and language scores.

        >>> p = SchemaPredictor()
        >>> p.initialize()
        >>> p.restore_learned("users\\norders\\nproducts")
        >>> p.get_stats()["learned_values"]
        3
        >>> candidates = p.predict("user")
        >>> any(c[0] == "users" for c in candidates)
        True
        """

        if not data:
            return

        if not self._initialized:
            self.initialize()

        values = [v.strip() for v in data.split("\n") if v.strip()]

        restored = 0
        for value in values:
            if value not in self._learned_values:
                self.learn(value)
                restored += 1

        if restored:
            debugMsg = "predictor restored %d learned values from session" % restored
            logger.debug(debugMsg)
