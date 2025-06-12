package org.owasp.untrust.boxedpath;

import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class PathSandboxFullCoverageTest {

    @Test
    void testBoxrootInitializationWithString() throws IOException {
        PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure/sandbox");
        assertNotNull(sandbox);
        assertEquals(Path.of("/secure/sandbox").toAbsolutePath().normalize(), 
                     sandbox.getRoot().getUnprotectedPath().toAbsolutePath().normalize());
    }

    @Test
    void testBoxrootWithMultiplePathSegments() throws IOException {
        PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure", "sandbox");
        assertEquals(Path.of("/secure/sandbox").toAbsolutePath().normalize(),
                     sandbox.getRoot().getUnprotectedPath().toAbsolutePath().normalize());
    }

    @Test
    void testResolveString() throws IOException {
        PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure/sandbox");
        BoxedPath boxedPath = sandbox.resolve("file.txt");
        assertEquals(Path.of("/secure/sandbox", "file.txt").toAbsolutePath(), 
                     boxedPath.toAbsolutePath().getUnprotectedPath());
    }

    @Test
    void testResolvePathObject() throws IOException {
        PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure/sandbox");
        Path path = Path.of("x", "file.txt");
        BoxedPath boxedPath = sandbox.resolve(path);
        assertEquals(Path.of("/secure/sandbox", "x", "file.txt").toAbsolutePath(), 
                     boxedPath.toAbsolutePath().getUnprotectedPath());
    }

    @Test
    void testOfMethodWithPathObject() throws IOException {
        PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure/sandbox");
        BoxedPath boxedPath = sandbox.of(Path.of("/secure/sandbox/file.txt"));
        assertEquals(Path.of("/secure/sandbox/file.txt").toAbsolutePath().normalize(),
                     boxedPath.getUnprotectedPath().toAbsolutePath().normalize());
    }

    @Test
    void testOfMethodWithStrings() throws IOException {
        PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure/sandbox");
        BoxedPath boxedPath = sandbox.of("/secure", "sandbox", "file.txt");
        assertEquals(Path.of("/secure/sandbox/file.txt").toAbsolutePath(),
                     boxedPath.toAbsolutePath().getUnprotectedPath());
    }

    @Test
    void testOfMethodOutsideSandboxThrows() throws IOException {
        PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure/sandbox");
        assertThrows(SecurityException.class, () -> 
            sandbox.of(Path.of("/outside/sandbox/file.txt")));
    }

    @Test
    void testOfMethodWithStringsOutsideSandboxThrows() throws IOException {
        PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure/sandbox");
        assertThrows(SecurityException.class, () -> 
            sandbox.of("file1.txt")); // file1.txt is relative to cwd and not to /secure/sandbox so it is outside sandbox
    }

    @Test
    void testGetFileSystemNotNull() throws IOException {
        PathSandbox sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure/sandbox");
        assertNotNull(sandbox.getFileSystem());
    }
}
