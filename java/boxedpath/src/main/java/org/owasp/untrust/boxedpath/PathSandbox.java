package org.owasp.untrust.boxedpath;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.Collections;

public class PathSandbox {
    public static PathSandbox boxroot(@NotNull Path sandboxRoot) throws IOException {
        return new PathSandbox(sandboxRoot);
    }

    public static PathSandbox boxroot(String first, String... more) throws IOException {
        Path constructedPath = Path.of(first, more);
        return new PathSandbox(constructedPath);
    }

    private final BoxedFileSystem m_fs;

    private PathSandbox(@NotNull Path sandboxRoot) throws IOException {
        m_fs = getFilesystem(sandboxRoot);
    }

    private static BoxedFileSystem getFilesystem(@NotNull Path sandboxRoot) {
        try {
            return (BoxedFileSystem) FileSystems.newFileSystem(BoxedPath.toUri(sandboxRoot), Collections.emptyMap());
        }
        catch (FileSystemAlreadyExistsException | IOException ex) {
            return (BoxedFileSystem) FileSystems.getFileSystem(BoxedPath.toUri(sandboxRoot));
        }
    }

    public @NotNull BoxedPath getRoot() {
        return BoxedPath.of(this, this.m_fs.getSandboxAbsolutePath());
    }

    public @NotNull BoxedPath of(@NotNull Path path) {
        return BoxedPath.of(this, path);
    }

    public @NotNull BoxedPath of(@NotNull String first, @NotNull String... more) {
        return BoxedPath.of(this, first, more);
    }

    public @NotNull BoxedPath resolve(@NotNull Path other) {
        return getRoot().resolve(other);
    }

    public @NotNull BoxedPath resolve(@NotNull String other) {
        return resolve(Path.of(other));
    }

    BoxedFileSystem getFileSystem() { return m_fs; }
}
