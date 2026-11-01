package org.safeguardian.vault

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.view.View
import android.widget.RemoteViews

/**
 * Locked Android Autofill provider for native apps ONLY. Never loads plaintext
 * secrets during onFillRequest. The request is authenticated by AutofillUnlockActivity,
 * which unlocks the vault, matches the actual calling Android package, and requires
 * explicit user selection. Browser origins require dedicated domain verification
 * and are purposefully not filled by this prototype.
 */
class GuardianAutofillService : AutofillService() {
    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        if (!AuthStore(this).initialized || cancellationSignal.isCanceled) {
            callback.onSuccess(null)
            return
        }
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }
        val requester = structure.activityComponent?.packageName ?: ""
        if (requester == packageName || requester.isBlank() || isBrowser(requester)) {
            callback.onSuccess(null)
            return
        }
        val fields = detect(structure)
        val passwordId = fields.second
        if (passwordId == null) {
            callback.onSuccess(null)
            return
        }

        val ids = listOfNotNull(fields.first, passwordId).distinct().toTypedArray()
        val intent = Intent(this, AutofillUnlockActivity::class.java).apply {
            putExtra(AutofillUnlockActivity.EXTRA_CALLER, requester)
            putExtra(AutofillUnlockActivity.EXTRA_LOGIN_ID, fields.first)
            putExtra(AutofillUnlockActivity.EXTRA_PASSWORD_ID, passwordId)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        val sender = PendingIntent.getActivity(this, 719, intent, flags).intentSender
        val display = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, "SafeGuardian — открыть пароли")
        }
        val reply = FillResponse.Builder().setAuthentication(ids, sender, display).build()
        callback.onSuccess(reply)
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Never silently capture credentials from third-party apps.
        callback.onSuccess()
    }

    private fun detect(structure: AssistStructure): Pair<AutofillId?, AutofillId?> {
        var username: AutofillId? = null
        var password: AutofillId? = null
        fun scan(node: AssistStructure.ViewNode) {
            val hints = node.autofillHints?.map { it.lowercase() } ?: emptyList()
            val isInput = node.autofillType == View.AUTOFILL_TYPE_TEXT
            if (isInput) {
                if (username == null && hints.any {
                    it.contains("username") || it.contains("email") || it.contains("login")
                }) username = node.autofillId
                if (password == null && hints.any { it.contains("password") })
                    password = node.autofillId
            }
            for (index in 0 until node.childCount) scan(node.getChildAt(index))
        }
        for (i in 0 until structure.windowNodeCount) {
            scan(structure.getWindowNodeAt(i).rootViewNode)
        }
        return username to password
    }

    companion object {
        fun isBrowser(pkg: String): Boolean = pkg in setOf(
            "com.android.chrome", "com.chrome.beta", "com.chrome.dev",
            "org.mozilla.firefox", "org.mozilla.fenix",
            "com.microsoft.emmx", "com.brave.browser",
            "com.opera.browser", "com.opera.mini.native",
            "com.sec.android.app.sbrowser", "com.vivaldi.browser",
            "com.duckduckgo.mobile.android", "com.yandex.browser",
            "com.kiwibrowser.browser"
        )
    }
}
