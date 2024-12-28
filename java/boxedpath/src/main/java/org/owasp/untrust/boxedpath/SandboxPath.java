package org.owasp.untrust.boxedpath;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.Collections;

public class SandboxPath {
    public static SandboxPath boxroot(@NotNull Path sandboxRoot) throws IOException {
        return new SandboxPath(sandboxRoot);
    }

    public static SandboxPath boxroot(String first, String... more) throws IOException {
        Path constructedPath = Path.of(first, more);
        return new SandboxPath(constructedPath);
    }

    private final BoxedFileSystem m_fs;

    private SandboxPath(@NotNull Path sandboxRoot) throws IOException {
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

    BoxedFileSystem getFileSystem() { return m_fs; }
}
