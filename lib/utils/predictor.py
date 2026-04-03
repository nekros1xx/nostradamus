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
        self._collect(node, results)

        if length_filter is not None:
            results = [r for r in results if len(r[0]) == length_filter]

        results.sort(key=lambda x: -x[1])
        return results[:max_results]

    def _collect(self, node, results):
        """
        Recursively collect all words from a given node
        """

        if node.is_end:
            results.append((node.value, node.weight))

        for child in node.children.values():
            self._collect(child, results)

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
    WEIGHT_PATTERN_DERIVED = 80   # derived from naming patterns
    WEIGHT_COMMON_OUTPUTS = 60    # from common-outputs.txt
    WEIGHT_STATIC_DICT = 40       # from common-tables/columns.txt
    WEIGHT_LANGUAGE_DICT = 20     # from language dictionaries

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

            self._initialized = True

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
        Updates the trie, pattern analysis, and language detection.

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
            return []

        if max_results is None:
            max_results = self.MAX_CANDIDATES_TO_VERIFY

        # Search with original case
        candidates = self._trie.search_prefix(
            partial_value,
            max_results=max_results * 5,
            length_filter=length_filter
        )

        # Also search with lowercase (catches ALL_CAPS input matching lowercase dict)
        if partial_value != partial_value.lower():
            lower_candidates = self._trie.search_prefix(
                partial_value.lower(),
                max_results=max_results * 5,
                length_filter=length_filter
            )
            # Re-case the candidates to match the input style
            is_upper = partial_value == partial_value.upper()
            for val, weight in lower_candidates:
                if is_upper:
                    recased = val.upper()
                else:
                    recased = val
                candidates.append((recased, weight))

        # Deduplicate by lowercase key, keeping highest weight
        seen = {}
        for val, weight in candidates:
            key = val.lower()
            if key not in seen or weight > seen[key][1]:
                seen[key] = (val, weight)

        candidates = sorted(seen.values(), key=lambda x: -x[1])

        # Filter out the partial value itself
        candidates = [c for c in candidates if c[0].lower() != partial_value.lower()]

        return candidates[:max_results]

    def get_charset_hint(self, partial_value):
        """
        Returns a prioritized charset based on what characters are most likely
        at the next position, given the partial value so far.

        This is used as a fallback when no single candidate is strong enough
        to verify with a full equality check, but we can still optimize
        the bisection by reordering the charset.

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

        candidates = self._trie.search_prefix(partial_value, max_results=50)

        if not candidates:
            return []

        # Collect the next character from each candidate, weighted
        char_weights = {}
        for candidate_value, weight in candidates:
            if len(candidate_value) > len(partial_value):
                next_char = candidate_value[len(partial_value)]
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
        Returns a human-readable efficiency report string.
        Uses real timing data when available, falls back to estimates.
        """

        total_attempts = self.stats_hits + self.stats_misses
        if total_attempts == 0:
            return None

        net_queries = self.stats_queries_saved - self.stats_queries_wasted
        hit_rate = (100.0 * self.stats_hits / total_attempts) if total_attempts > 0 else 0

        # Determine timing source
        if self.stats_avg_query_time > 0:
            timing_source = "measured"
            avg_q_time = self.stats_avg_query_time
        else:
            timing_source = "estimated"
            avg_q_time = conf.get("timeSec") or 5

        net_time = self.stats_time_saved - self.stats_time_wasted

        lines = []
        lines.append("predictor stats - hits: %d, misses: %d, hit rate: %.0f%%" % (
            self.stats_hits, self.stats_misses, hit_rate))
        lines.append("predictor stats - queries saved: %d, queries wasted: %d, net: %+d queries" % (
            self.stats_queries_saved, self.stats_queries_wasted, net_queries))
        lines.append("predictor stats - avg query time: %.2fs (%s), time saved: %.1fs, time wasted: %.1fs" % (
            avg_q_time, timing_source, self.stats_time_saved, self.stats_time_wasted))

        if net_time > 0:
            lines.append("predictor verdict: BENEFICIAL (saved %.1fs = %.1f min)" % (net_time, net_time / 60.0))
        elif net_time < 0:
            lines.append("predictor verdict: DETRIMENTAL (wasted %.1fs = %.1f min, consider --no-predict)" % (abs(net_time), abs(net_time) / 60.0))
        else:
            lines.append("predictor verdict: NEUTRAL (no net effect)")

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
