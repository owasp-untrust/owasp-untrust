package org.owasp.untrust.boxedpath;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.file.Path;

class AbsoluteBoxrootTest {

    @Test
    void testRelativeBoxrootResolution() throws IOException {
        PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/sandbox");
        BoxedPath path = sandbox.resolve("allowed.txt");

        assertEquals(
            Path.of("/sandbox/allowed.txt").toAbsolutePath().normalize(),
            path.getUnprotectedPath().toAbsolutePath().normalize()
        );

        assertThrows(SecurityException.class, () -> sandbox.resolve("../outside.txt"));
    }
}
