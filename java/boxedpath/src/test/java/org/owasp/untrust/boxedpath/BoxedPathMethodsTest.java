package org.owasp.untrust.boxedpath;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;

class BoxedPathMethodsTest {

    PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure/sandbox");

    @Test
    void testResolveWithinSandbox() {
        BoxedPath resolvedWithinSandbox = sandbox.resolve("subdir/file.txt");
        Path resolvedPath = Path.of("/secure/sandbox", "subdir/file.txt");
        assertEquals(resolvedWithinSandbox.toAbsolutePath().getUnprotectedPath(), resolvedPath.toAbsolutePath());
    }

    @Test
    void testResolveOutsideSandboxThrows() {
        assertThrows(SecurityException.class, () -> sandbox.resolve("../../outside.txt"));
    }

    @Test
    void testNormalizeWithinSandbox() {
        BoxedPath path = sandbox.resolve("dir/../file.txt");
        assertEquals(sandbox.resolve("file.txt").normalize(), path.normalize());
    }

    @Test
    void testRelativizeWithinSandbox() {
        //BoxedPath path1 = sandbox.resolve("dir1/file.txt");
        //BoxedPath path2 = sandbox.resolve("dir2/file2.txt");
        //Path relativePath = path1.relativize(path2);
        assertThrowsExactly(
            SecurityException.class, 
            ()->sandbox.of("dir").relativize(sandbox.of("file.txt"))
        );
    }

    @Test
    void testToAbsolutePathWithoutExistingFile() {
        BoxedPath nonExistentPath = sandbox.resolve("doesNotExist.txt");
        assertDoesNotThrow(() -> nonExistentPath.toAbsolutePath());
    }
}
