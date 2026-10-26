package io.deltator

import org.junit.Assert.assertTrue
import org.junit.Test

class ReleaseCheckerTest {
    private fun older(a: String, b: String) = ReleaseChecker.compareVersions(a, b) < 0

    @Test fun ordersVersions() {
        assertTrue(older("1.0.0", "1.0.1"))
        assertTrue(older("1.0.1", "1.0.2-test1"))
        assertTrue(older("1.0.2-test1", "1.0.2"))
        assertTrue(older("1.0.2-test1", "1.0.2-test2"))
        assertTrue(older("1.0.9", "1.0.10"))
        assertTrue(older("1.9.0", "2.0.0"))
        assertTrue(ReleaseChecker.compareVersions("v1.0.1", "1.0.1") == 0)
        // the reported bug: a test build must not see 1.0.1 as an update
        assertTrue(!older("1.0.2-test1", "1.0.1"))
    }
}
