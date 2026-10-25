package io.deltator.routing

/**
 * The rule sets a country starts with, the way NekoBox fills its route list when a
 * country is picked on first launch.
 *
 * Every country gets the same two generic rules first (BitTorrent straight out,
 * ads blocked), then a domain rule and an IP rule that send that country's own
 * sites around Tor: domestic sites are reachable without Tor anyway, are often
 * slow or blocked from Tor exits, and some only answer domestic addresses.
 */
object RoutePresets {

    data class Country(
        val code: String,
        val name: String,
        val domains: List<String>,
        val ips: List<String>
    )

    /** The pseudo country that keeps only the generic rules. */
    const val NONE = "none"

    /**
     * Russian domestic domains, as wide as the data allows.
     *
     * Every Russian-run TLD is listed explicitly, Cyrillic ones in their punycode
     * form because that is what travels in SNI and DNS: .ru .su .рф .москва .рус
     * .дети .онлайн .сайт .орг .ком .moscow .tatar .yandex. On top of that the
     * curated v2fly lists of Russian services hosted under foreign TLDs, and the
     * runetfreedom list of sites that only answer Russian addresses.
     */
    private val RU_DOMAINS = listOf(
        "geosite:category-ru",
        "geosite:category-gov-ru",
        "geosite:ru-available-only-inside",
        "geosite:yandex",
        "geosite:vk",
        "geosite:mailru",
        "domain:ru",
        "domain:su",
        "domain:xn--p1ai",       // .рф
        "domain:xn--80adxhks",   // .москва
        "domain:xn--p1acf",      // .рус
        "domain:xn--d1acj3b",    // .дети
        "domain:xn--80asehdb",   // .онлайн
        "domain:xn--80aswg",     // .сайт
        "domain:xn--c1avg",      // .орг
        "domain:xn--j1aef",      // .ком
        "domain:moscow",
        "domain:tatar",
        "domain:yandex"
    )

    val COUNTRIES: List<Country> = listOf(
        Country("ru", "Russia", RU_DOMAINS, listOf("geoip:ru")),
        Country(
            "by", "Belarus",
            listOf("geosite:category-by", "domain:by", "domain:xn--90ais"), // .бел
            listOf("geoip:by")
        ),
        Country(
            "kz", "Kazakhstan",
            listOf("geosite:category-kz", "domain:kz", "domain:xn--80ao21a"), // .қаз
            listOf("geoip:kz")
        ),
        Country("uz", "Uzbekistan", listOf("domain:uz"), listOf("geoip:uz")),
        Country(
            "ua", "Ukraine",
            listOf("geosite:category-ua", "domain:ua", "domain:xn--j1amh"), // .укр
            listOf("geoip:ua")
        ),
        Country(
            "ir", "Iran",
            listOf("geosite:category-ir", "domain:ir", "domain:xn--mgba3a4f16a"), // .ایران
            listOf("geoip:ir")
        ),
        Country(
            "cn", "China",
            listOf("geosite:cn", "geosite:geolocation-cn", "domain:cn", "domain:xn--fiqs8s"), // .中国
            listOf("geoip:cn")
        ),
        Country("tr", "Turkey", listOf("geosite:category-tr", "domain:tr"), listOf("geoip:tr")),
        Country("tm", "Turkmenistan", listOf("domain:tm"), listOf("geoip:tm"))
    )

    fun country(code: String): Country? = COUNTRIES.firstOrNull { it.code == code }

    fun displayName(code: String): String = country(code)?.name ?: "No country"

    /** The default list for [code]; [NONE] or an unknown code keeps the generic rules only. */
    fun defaults(code: String): List<RouteRule> {
        var id = System.currentTimeMillis()
        val rules = mutableListOf(
            RouteRule(
                id = id++,
                name = "BitTorrent direct",
                protocols = listOf("bittorrent"),
                outbound = RouteOutbound.BYPASS
            ),
            RouteRule(
                id = id++,
                name = "Block ads",
                domains = listOf("geosite:category-ads-all"),
                outbound = RouteOutbound.BLOCK
            )
        )
        val c = country(code) ?: return rules
        rules += RouteRule(
            id = id++,
            name = "Domain rule for ${c.name}",
            domains = c.domains,
            outbound = RouteOutbound.BYPASS
        )
        rules += RouteRule(
            id = id,
            name = "IP rule for ${c.name}",
            ips = c.ips,
            outbound = RouteOutbound.BYPASS
        )
        return rules
    }
}
