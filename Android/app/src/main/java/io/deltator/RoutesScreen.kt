package io.deltator

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.deltator.routing.GeoUpdater
import io.deltator.routing.RouteOutbound
import io.deltator.routing.RoutePresets
import io.deltator.routing.RouteRule
import io.deltator.routing.RouteStore
import io.deltator.ui.DeltaTor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

/**
 * The route list, NekoBox style: one card per rule, top to bottom in the order
 * they are tried, each with its conditions, where it sends traffic and a switch.
 * Tapping a card edits it; the country picker resets the list to that
 * country's defaults.
 */
@Composable
internal fun RoutesScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val rules by RouteStore.rules.collectAsStateWithLifecycle()
    val country by RouteStore.country.collectAsStateWithLifecycle()
    var routingOn by remember { mutableStateOf(Config.routingEnabled) }
    var editing by remember { mutableStateOf<RouteRule?>(null) }
    var pickCountry by remember { mutableStateOf(false) }
    var updating by remember { mutableStateOf(false) }
    var updateStatus by remember { mutableStateOf("") }
    var updatedAt by remember { mutableStateOf(Config.routesUpdatedAt) }

    BackHandler(onBack = onBack)

    Box(
        Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.systemBars)
            .background(Brush.verticalGradient(listOf(Color(0xFF1B2030), DeltaTor.Bg, Color(0xFF0C0E15))))
    ) {
        Column(Modifier.fillMaxSize()) {
            ScreenTopBar("ROUTES", onBack) {
                IconAction(Icons.Filled.Add, "Add rule") {
                    editing = RouteRule(id = RouteStore.newId(), name = "", outbound = RouteOutbound.BYPASS)
                }
            }
            LazyColumn(
                Modifier.fillMaxSize(),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 28.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                item(key = "head") {
                    RoutesCard {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text("Apply rules", style = MaterialTheme.typography.titleSmall, color = DeltaTor.Text)
                                Text(
                                    if (routingOn) "Applies to new connections right away"
                                    else "Off: everything goes through Tor",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = DeltaTor.Muted
                                )
                            }
                            ToggleSwitch(routingOn) {
                                routingOn = it
                                RouteStore.setRoutingEnabled(it)
                            }
                        }
                        Spacer(Modifier.height(12.dp))
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .clickable { pickCountry = true }
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text("Country", style = MaterialTheme.typography.titleSmall, color = DeltaTor.Text)
                                Text(
                                    if (country == RoutePresets.NONE) "No country · generic rules only"
                                    else "${flagEmoji(country)}  ${RoutePresets.displayName(country)}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = DeltaTor.Muted
                                )
                            }
                            Text("CHANGE", style = labelBold(), color = DeltaTor.AccentLight)
                        }
                        Spacer(Modifier.height(6.dp))
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .clickable(enabled = !updating) {
                                    updating = true
                                    scope.launch {
                                        val result = withContext(Dispatchers.IO) {
                                            GeoUpdater.update(context, rules) { msg ->
                                                scope.launch { updateStatus = msg }
                                            }
                                        }
                                        updating = false
                                        updateStatus = result.message
                                        updatedAt = Config.routesUpdatedAt
                                        if (result.ok) RouteStore.reapply()
                                    }
                                }
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text("Site and IP lists", style = MaterialTheme.typography.titleSmall, color = DeltaTor.Text)
                                Text(
                                    updateStatus.ifEmpty {
                                        if (updatedAt == 0L) "Bundled with the app"
                                        else "Updated " + DateFormat.getDateTimeInstance(
                                            DateFormat.MEDIUM, DateFormat.SHORT
                                        ).format(Date(updatedAt))
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = DeltaTor.Muted
                                )
                            }
                            Text(
                                if (updating) "…" else "UPDATE",
                                style = labelBold(),
                                color = if (updating) DeltaTor.Muted else DeltaTor.AccentLight
                            )
                        }
                    }
                }
                item(key = "warn") {
                    RoutesCard {
                        Text(
                            "Rules are tried top to bottom; the first match wins, and anything " +
                                "unmatched goes through Tor. Bypass sends traffic straight to the " +
                                "internet, outside Tor. Read the docs before adding your own rules, " +
                                "or the internet may stop working.",
                            style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.SemiBold, lineHeight = 17.sp),
                            color = DeltaTor.Text.copy(alpha = 0.85f)
                        )
                    }
                }
                if (rules.isEmpty()) {
                    item(key = "empty") {
                        Text(
                            "No rules. Everything goes through Tor.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = DeltaTor.Muted,
                            modifier = Modifier.padding(8.dp)
                        )
                    }
                }
                items(rules, key = { it.id }) { rule ->
                    RuleCard(
                        rule = rule,
                        dimmed = !routingOn,
                        onEdit = { editing = rule },
                        onCopy = { RouteStore.duplicate(rule.id) },
                        onToggle = { RouteStore.setEnabled(rule.id, it) }
                    )
                }
            }
        }
    }

    editing?.let { rule ->
        RuleEditor(
            initial = rule,
            isNew = rules.none { it.id == rule.id },
            onDismiss = { editing = null },
            onSave = { RouteStore.put(it); editing = null },
            onDelete = { RouteStore.delete(rule.id); editing = null },
            onMove = { RouteStore.move(rule.id, it) }
        )
    }

    if (pickCountry) {
        CountryPickerDialog(
            title = "Reset rules for a country",
            note = "This replaces the whole rule list with the defaults for the country you pick.",
            current = country,
            onDismiss = { pickCountry = false },
            onPick = {
                RouteStore.selectCountry(it)
                Config.routesCountryChosen = true
                pickCountry = false
            }
        )
    }
}

/**
 * The first-launch question, as in NekoBox: which country are you in, so the
 * route list can start on that country's defaults.
 */
@Composable
internal fun FirstRunCountryDialog(onDone: () -> Unit) {
    CountryPickerDialog(
        title = "Where are you?",
        note = "Sites of your country will be opened directly, without Tor, which keeps them " +
            "fast and working. Ads are blocked and BitTorrent goes direct. You can change all " +
            "of it later under Controls → Routes.",
        current = Config.routesCountry,
        onDismiss = {
            // Dismissing keeps the preselected defaults and does not ask again.
            Config.routesCountryChosen = true
            onDone()
        },
        onPick = {
            RouteStore.selectCountry(it)
            Config.routesCountryChosen = true
            onDone()
        }
    )
}

@Composable
private fun CountryPickerDialog(
    title: String,
    note: String,
    current: String,
    onDismiss: () -> Unit,
    onPick: (String) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = DeltaTor.Surface,
        title = { Text(title, color = DeltaTor.Text) },
        text = {
            Column(Modifier.heightIn(max = 460.dp).verticalScroll(rememberScrollState())) {
                Text(note, style = MaterialTheme.typography.bodySmall, color = DeltaTor.Muted)
                Spacer(Modifier.height(10.dp))
                for (c in RoutePresets.COUNTRIES) {
                    PickRow("${flagEmoji(c.code)}  ${c.name}", c.code == current) { onPick(c.code) }
                }
                PickRow("🌐  No country (generic rules only)", current == RoutePresets.NONE) {
                    onPick(RoutePresets.NONE)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("CANCEL", color = DeltaTor.AccentLight) }
        }
    )
}

@Composable
private fun PickRow(label: String, selected: Boolean, onClick: () -> Unit) {
    Text(
        label,
        style = MaterialTheme.typography.bodyLarge,
        color = if (selected) DeltaTor.AccentLight else DeltaTor.Text,
        fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(if (selected) DeltaTor.Accent.copy(alpha = 0.14f) else Color.Transparent)
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 11.dp)
    )
}

@Composable
private fun RuleCard(
    rule: RouteRule,
    dimmed: Boolean,
    onEdit: () -> Unit,
    onCopy: () -> Unit,
    onToggle: (Boolean) -> Unit
) {
    val lines = remember(rule) { rule.summaryLines() }
    RoutesCard(Modifier.clickable(onClick = onEdit)) {
        Row(verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f)) {
                Text(
                    rule.name.ifBlank { "Unnamed rule" },
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = if (dimmed || !rule.enabled) DeltaTor.Muted else DeltaTor.Text,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(Modifier.height(10.dp))
                for (line in lines.take(3)) {
                    Text(
                        line,
                        style = MaterialTheme.typography.bodyMedium,
                        color = DeltaTor.Muted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                if (lines.size > 3) Text("…", style = MaterialTheme.typography.bodyMedium, color = DeltaTor.Muted)
                Spacer(Modifier.height(4.dp))
                Text(
                    rule.outbound.label,
                    style = MaterialTheme.typography.bodyMedium,
                    color = outboundColor(rule.outbound)
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Row {
                    IconAction(Icons.Filled.Edit, "Edit", onEdit)
                    IconAction(Icons.Filled.ContentCopy, "Duplicate", onCopy)
                }
                Spacer(Modifier.height(18.dp))
                ToggleSwitch(rule.enabled, onToggle)
            }
        }
    }
}

private val PROTOCOL_CHOICES = listOf("bittorrent", "tls", "http")

@Composable
private fun RuleEditor(
    initial: RouteRule,
    isNew: Boolean,
    onDismiss: () -> Unit,
    onSave: (RouteRule) -> Unit,
    onDelete: () -> Unit,
    onMove: (Int) -> Unit
) {
    var name by remember { mutableStateOf(initial.name) }
    var domains by remember { mutableStateOf(initial.domains.joinToString("\n")) }
    var ips by remember { mutableStateOf(initial.ips.joinToString("\n")) }
    var ports by remember { mutableStateOf(initial.ports) }
    var protocols by remember { mutableStateOf(initial.protocols.toSet()) }
    var outbound by remember { mutableStateOf(initial.outbound) }

    fun current() = initial.copy(
        name = name.trim(),
        domains = RouteRule.splitLines(domains),
        ips = RouteRule.splitLines(ips),
        ports = ports.trim(),
        protocols = PROTOCOL_CHOICES.filter { it in protocols },
        outbound = outbound
    )

    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Column(
            Modifier
                .fillMaxSize()
                .background(DeltaTor.Bg)
                .windowInsetsPadding(WindowInsets.systemBars)
                .imePadding()
        ) {
            ScreenTopBar(if (isNew) "NEW RULE" else "EDIT RULE", onDismiss) {
                if (!isNew) {
                    IconAction(Icons.Filled.ArrowUpward, "Move up") { onMove(-1) }
                    IconAction(Icons.Filled.ArrowDownward, "Move down") { onMove(1) }
                    IconAction(Icons.Filled.Delete, "Delete", onDelete)
                }
            }
            Column(
                Modifier
                    .weight(1f)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 12.dp)
            ) {
                Field("Name", name, singleLine = true) { name = it }
                Field(
                    "Domains, one per line",
                    domains,
                    hint = "geosite:category-ru\ndomain:example.com\nfull:www.example.com\nkeyword:shop\nregexp:\\.ru$"
                ) { domains = it }
                Field("IPs, one per line", ips, hint = "geoip:ru\ngeoip:private\n192.168.0.0/16") { ips = it }
                Field("Ports", ports, singleLine = true, hint = "80,443,1000-2000") { ports = it }

                SectionLabel("PROTOCOL")
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    for (p in PROTOCOL_CHOICES) {
                        Chip(p, p in protocols, DeltaTor.AccentLight) {
                            protocols = if (p in protocols) protocols - p else protocols + p
                        }
                    }
                }
                Spacer(Modifier.height(14.dp))
                SectionLabel("OUTBOUND")
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    for (o in RouteOutbound.entries) {
                        Chip(o.label, outbound == o, outboundColor(o)) { outbound = o }
                    }
                }
                Spacer(Modifier.height(14.dp))
                Text(
                    "Fields are combined: a rule matches when every filled field matches. " +
                        "Inside a field any line may match. Domain rules see the site name from " +
                        "the connection (TLS SNI or HTTP Host).",
                    style = MaterialTheme.typography.bodySmall,
                    color = DeltaTor.Muted
                )
            }
            val valid = !current().isEmpty
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.End
            ) {
                TextButton(onClick = onDismiss) { Text("CANCEL", color = DeltaTor.Muted) }
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = { onSave(current()) }, enabled = valid) {
                    Text("SAVE", color = if (valid) DeltaTor.AccentLight else DeltaTor.Muted)
                }
            }
        }
    }
}

@Composable
private fun Field(
    label: String,
    value: String,
    singleLine: Boolean = false,
    hint: String = "",
    onChange: (String) -> Unit
) {
    SectionLabel(label.uppercase())
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        singleLine = singleLine,
        minLines = if (singleLine) 1 else 3,
        textStyle = TextStyle(fontSize = 14.sp, color = DeltaTor.Text),
        colors = AdvancedFieldColors(),
        placeholder = { if (hint.isNotEmpty()) Text(hint, fontSize = 13.sp) },
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(Modifier.height(14.dp))
}

@Composable
private fun SectionLabel(text: String) {
    Text(text, style = labelBold(), color = DeltaTor.Muted, modifier = Modifier.padding(bottom = 6.dp))
}

@Composable
private fun Chip(label: String, active: Boolean, color: Color, onClick: () -> Unit) {
    Text(
        label,
        style = labelBold(),
        color = if (active) Color(0xFF08111A) else DeltaTor.Muted,
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(if (active) color else Color.Transparent)
            .border(1.dp, if (active) color else DeltaTor.BorderLight, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 8.dp)
    )
}

@Composable
private fun IconAction(icon: ImageVector, description: String, onClick: () -> Unit) {
    Box(
        Modifier
            .size(40.dp)
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Icon(icon, contentDescription = description, tint = DeltaTor.Muted, modifier = Modifier.size(22.dp))
    }
}

@Composable
private fun RoutesCard(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    val shape = RoundedCornerShape(16.dp)
    Column(
        Modifier
            .fillMaxWidth()
            .clip(shape)
            .background(DeltaTor.SurfaceAlt, shape)
            .then(modifier)
            .padding(horizontal = 16.dp, vertical = 14.dp)
    ) { content() }
}

private fun outboundColor(o: RouteOutbound): Color = when (o) {
    RouteOutbound.BYPASS -> DeltaTor.Green
    RouteOutbound.BLOCK -> DeltaTor.Red
    RouteOutbound.PROXY -> DeltaTor.AccentLight
}

@Composable
private fun labelBold() = MaterialTheme.typography.labelSmall.copy(letterSpacing = 1.1.sp, fontWeight = FontWeight.Bold)
