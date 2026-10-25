package io.deltator.routing

import android.content.Context
import io.deltator.Config
import io.deltator.util.AppLog as Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.json.JSONArray
import java.io.File

/**
 * The route list: what the Routes screen edits and what a connect compiles.
 *
 * Stored as JSON in the app's files. A fresh install starts on the defaults of
 * the country picked on first launch (Russia is preselected there). Every edit
 * is saved at once and, while connected, recompiled and handed to the bridge,
 * so a rule switched off applies to the next connection without a reconnect.
 */
object RouteStore {
    private const val TAG = "RouteStore"
    private const val FILE = "routes.json"

    private lateinit var appContext: Context
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var applyJob: Job? = null

    private val _rules = MutableStateFlow<List<RouteRule>>(emptyList())
    val rules: StateFlow<List<RouteRule>> = _rules.asStateFlow()

    private val _country = MutableStateFlow(RoutePresets.NONE)
    val country: StateFlow<String> = _country.asStateFlow()

    /** Called with the freshly compiled router after every change. */
    @Volatile var onCompiled: ((Router) -> Unit)? = null

    fun init(context: Context) {
        appContext = context.applicationContext
        _country.value = Config.routesCountry
        _rules.value = load() ?: RoutePresets.defaults(_country.value).also { save(it) }
    }

    fun setEnabled(id: Long, enabled: Boolean) = edit { list ->
        list.map { if (it.id == id) it.copy(enabled = enabled) else it }
    }

    /** Insert or replace by id; a new rule goes to the end. */
    fun put(rule: RouteRule) = edit { list ->
        if (list.any { it.id == rule.id }) list.map { if (it.id == rule.id) rule else it }
        else list + rule
    }

    fun duplicate(id: Long) = edit { list ->
        val i = list.indexOfFirst { it.id == id }
        if (i < 0) list
        else list.toMutableList().apply {
            add(i + 1, list[i].copy(id = newId(), name = list[i].name + " (copy)"))
        }
    }

    fun delete(id: Long) = edit { list -> list.filterNot { it.id == id } }

    fun move(id: Long, delta: Int) = edit { list ->
        val i = list.indexOfFirst { it.id == id }
        val j = i + delta
        if (i < 0 || j !in list.indices) list
        else list.toMutableList().apply { add(j, removeAt(i)) }
    }

    /** Pick a country and replace the whole list with its defaults. */
    fun selectCountry(code: String) {
        Config.routesCountry = code
        _country.value = code
        edit { RoutePresets.defaults(code) }
    }

    fun newId(): Long = maxOf(System.currentTimeMillis(), (_rules.value.maxOfOrNull { it.id } ?: 0L) + 1)

    /**
     * Compile the current list now, on the calling thread; [Router.DISABLED]
     * while routing is switched off.
     */
    fun compile(): Router =
        if (Config.routingEnabled) Router.compile(appContext, _rules.value) else Router.DISABLED

    fun setRoutingEnabled(on: Boolean) {
        Config.routingEnabled = on
        reapply()
    }

    /** Recompile in the background and hand the result to [onCompiled]. */
    fun reapply() {
        val listener = onCompiled ?: return
        val snapshot = _rules.value
        applyJob?.cancel()
        applyJob = scope.launch {
            val router = compile()
            if (_rules.value === snapshot) listener(router)
        }
    }

    private fun edit(change: (List<RouteRule>) -> List<RouteRule>) {
        val next = change(_rules.value)
        if (next == _rules.value) return
        _rules.value = next
        save(next)
        reapply()
    }

    private fun load(): List<RouteRule>? {
        val file = File(appContext.filesDir, FILE)
        if (!file.isFile) return null
        return try {
            val arr = JSONArray(file.readText())
            (0 until arr.length()).map { RouteRule.fromJson(arr.getJSONObject(it)) }
        } catch (e: Exception) {
            Log.e(TAG, "routes.json unreadable, starting over: ${e.message}")
            null
        }
    }

    private fun save(list: List<RouteRule>) {
        try {
            val file = File(appContext.filesDir, FILE)
            val tmp = File(appContext.filesDir, "$FILE.tmp")
            tmp.writeText(JSONArray().apply { list.forEach { put(it.toJson()) } }.toString())
            if (!tmp.renameTo(file)) { tmp.copyTo(file, true); tmp.delete() }
        } catch (e: Exception) {
            Log.e(TAG, "routes.json write failed: ${e.message}")
        }
    }
}
