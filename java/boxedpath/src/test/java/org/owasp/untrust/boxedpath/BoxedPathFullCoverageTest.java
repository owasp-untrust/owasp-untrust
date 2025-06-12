package org.owasp.untrust.boxedpath;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.FileAttribute;

class BoxedPathFullCoverageTest {

    PathSandbox sandbox;

    BoxedPathFullCoverageTest() throws IOException {
        sandbox = PathSandbox.boxroot(SandboxJailbreak.UNCHECKED_SYMLINKS, "/secure/sandbox");
    }

    @Test
    void testOfMethod() {
        BoxedPath path = BoxedPath.of(sandbox, "test.txt");
        assertEquals(Path.of("/secure/sandbox/test.txt").toAbsolutePath(), path.toAbsolutePath().getUnprotectedPath());
    }

    @Test
    void testResolve() {
        BoxedPath path = sandbox.resolve("sub/file.txt");
        assertEquals(sandbox.resolve("sub").resolve("file.txt"), path);
        assertEquals(
        sandbox.getRoot().resolve("sub/file.txt").getUnprotectedAbsoluteSandbox(), 
        path.toAbsolutePath().getUnprotectedAbsoluteSandbox());
    }

    @Test
    void testResolveSibling() {
        BoxedPath original = sandbox.resolve("dir/file.txt");
        BoxedPath sibling = original.resolveSibling("sibling.txt");
        assertEquals(sandbox.resolve("dir/sibling.txt"), sibling);
    }

    @Test
    void testNormalize() {
        BoxedPath path = sandbox.resolve("dir/../file.txt").normalize();
        assertEquals(sandbox.resolve("file.txt"), path);
    }

    @Test
    void testRelativize() {
        BoxedPath path1 = sandbox.resolve("dir1/file.txt");
        BoxedPath path2 = sandbox.resolve("dir2/other.txt");
        assertThrowsExactly(
            SecurityException.class,
            ()->path1.relativize(path2)
        );
    }

    @Test
    void testGetFileName() {
        BoxedPath path = sandbox.resolve("dir/file.txt");
        assertEquals(Paths.get("file.txt"), path.getFileName());
    }

    @Test
    void testGetParent() {
        BoxedPath path = sandbox.resolve("dir/file.txt");
        assertEquals(sandbox.resolve("dir"), path.getParent());
    }

    @Test
    void testGetRoot() {
        BoxedPath path = sandbox.resolve("file.txt");
        assertEquals(sandbox.getRoot().getRoot(), path.getRoot());
    }

    @Test
    void testIsAbsolute() {
        BoxedPath path = sandbox.resolve("file.txt");
        assertEquals(path.getUnprotectedPath().isAbsolute(), path.isAbsolute());
    }

    @Test
    void testToAbsolutePath() {
        BoxedPath path = sandbox.resolve("file.txt");
        assertDoesNotThrow(path::toAbsolutePath);
    }

    @Test
    void testToRealPath() {
        PathSandbox existingSandbox = PathSandbox.boxroot(".");
        BoxedPath path = existingSandbox.resolve("sandboxTest");
        assertDoesNotThrow(()->Files.createDirectories(path));
        assertDoesNotThrow(() -> path.toRealPath());
    }

    @Test
    void testToRealPathOnPathWithNonExistingLastPart() {
        PathSandbox existingSandbox = PathSandbox.boxroot(".");
        BoxedPath path = existingSandbox.resolve("sandboxTest");
        BoxedPath withNonExistingLastPart = path.resolve("doesntExist");
        assertDoesNotThrow(()->Files.createDirectories(path));
        assertDoesNotThrow(() -> path.toRealPath());
        assertThrows(IOException.class, ()->withNonExistingLastPart.toRealPath());
    }

    @Test
    void testSymlinks() {
        PathSandbox existingSandbox = PathSandbox.boxroot(".");
        BoxedPath path = existingSandbox.resolve("sandboxTest");
        BoxedPath symlink = existingSandbox.resolve("sandboxLinkWithin");
        assertDoesNotThrow(()->Files.createDirectories(path));

        if (!Files.exists(symlink)) {
           assertDoesNotThrow(()->Files.createSymbolicLink(symlink.getUnprotectedPath(), path.getUnprotectedPath()));
        }
        BoxedPath withinSymlink = symlink.resolve("doesntExist");
        BoxedPath withinSymlink2 = existingSandbox.of(".", "sandboxLinkWithin", "doesntExist");
    }

    @Test
    void testSymlinksJailbreakPrevention() {
        Path sandboxPath = Path.of("sandboxTest");
        assertDoesNotThrow(()->Files.createDirectories(sandboxPath));
        assertDoesNotThrow(()->Files.createDirectories(sandboxPath.resolve("s1")));

        PathSandbox existingSandbox = PathSandbox.boxroot(sandboxPath);
        Path pathOutside = sandboxPath.resolve("..");

        // next I calculate the path to the link - has to be a Path because a BoxedPAth will throw a security exception
        Path jailbreakSymlink = sandboxPath.resolve("sandboxLinkOutside");
        if (!Files.exists(jailbreakSymlink)) {
            assertDoesNotThrow(()->Files.createSymbolicLink(jailbreakSymlink, pathOutside));
        }
        
        assertThrows(SecurityException.class, ()->existingSandbox.of(jailbreakSymlink));
        assertDoesNotThrow(()->existingSandbox.of(jailbreakSymlink.resolve("sandboxTest")));
        assertDoesNotThrow(()->existingSandbox.of("sandboxTest", "sandboxLinkOutside", "sandboxTest", "s1"));
        assertDoesNotThrow(()->existingSandbox.of("sandboxTest", "sandboxLinkOutside", "sandboxTest", "s2"));
    }

    @Test
    void testIterator() {
        BoxedPath path = sandbox.resolve("dir/file.txt");
        assertNotNull(path.iterator());
    }

    @Test
    void testCompareTo() {
        BoxedPath path1 = sandbox.resolve("a.txt");
        BoxedPath path2 = sandbox.resolve("b.txt");
        assertTrue(path1.compareTo(path2) < 0);
    }

    @Test
    void testToString() {
        BoxedPath path = sandbox.resolve("file.txt");
        assertEquals(path.getUnprotectedPath().toString(), path.toString());
    }

    @Test
    void testToUri() {
        BoxedPath path = sandbox.resolve("file.txt");
        URI uri = path.toUri();
        assertTrue(uri.toString().startsWith("sandbox:"));
    }

    @Test
    void testWatchKeyRegistration() {
        PathSandbox existingSandbox = PathSandbox.boxroot(".");
        BoxedPath path = existingSandbox.resolve("sandboxTest");
        assertDoesNotThrow(()->Files.createDirectories(path));

        assertDoesNotThrow(() -> {
            try (WatchService watcher = path.getFileSystem().newWatchService()) {
                WatchKey key = path.register(watcher, new WatchEvent.Kind<?>[]{StandardWatchEventKinds.ENTRY_MODIFY});
                assertNotNull(key);
                key.cancel();
            }
        });
    }

    @Test
    void testStartsWithAndEndsWith() {
        BoxedPath path = sandbox.resolve("dir/file.txt");
        assertTrue(path.startsWith(sandbox.resolve("dir").getUnprotectedAbsoluteSandbox()));
        assertTrue(path.endsWith("file.txt"));
    }

    @Test
    void testSubpath() {
        BoxedPath path = sandbox.resolve("a/b/c/file.txt");
        assertEquals(sandbox.resolve(Paths.get("b/c")), path.subpath(1, 3));
    }

    @Test
    void testEqualsAndHashCode() {
        BoxedPath path1 = sandbox.resolve("file.txt");
        BoxedPath path2 = sandbox.resolve("file.txt");
        assertEquals(path1, path2);
        assertEquals(path1.hashCode(), path2.hashCode());
    }

    @Test
    void testSecurityException() {
        assertThrows(SecurityException.class, () -> sandbox.resolve("../outside.txt"));
    }
}
