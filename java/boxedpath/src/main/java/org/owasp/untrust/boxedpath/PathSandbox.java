package org.owasp.untrust.boxedpath;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.Collections;

public class PathSandbox {
    public static PathSandbox boxroot(@NotNull Path sandboxRoot) {
        return new PathSandbox(sandboxRoot);
    }

    public static PathSandbox boxroot(SandboxJailbreak jailbreakPolicy, @NotNull Path sandboxRoot) {
        return new PathSandbox(jailbreakPolicy, sandboxRoot);
    }

    public static PathSandbox boxroot(String first, String... more) {
        Path constructedPath = Path.of(first, more);
        return new PathSandbox(constructedPath);
    }

    public static PathSandbox boxroot(SandboxJailbreak jailbreakPolicy, String first, String... more) {
        Path constructedPath = Path.of(first, more);
        return new PathSandbox(jailbreakPolicy, constructedPath);
    }

    private static BoxedFileSystem getFilesystem(SandboxJailbreak jailbreakPolicy, @NotNull Path sandboxRoot) {
        try {
            return (BoxedFileSystem) FileSystems.newFileSystem(BoxedPath.toUri(jailbreakPolicy, sandboxRoot), Collections.emptyMap());
        }
        catch (FileSystemAlreadyExistsException | IOException ex) {
            return (BoxedFileSystem) FileSystems.getFileSystem(BoxedPath.toUri(jailbreakPolicy, sandboxRoot));
        }
    }

    private final BoxedFileSystem m_fs;

    private PathSandbox(@NotNull Path sandboxRoot) {
        this(SandboxJailbreak.DISALLOW, sandboxRoot);
    }

    private PathSandbox(SandboxJailbreak jailbreakPolicy, @NotNull Path sandboxRoot) {
        m_fs = getFilesystem(jailbreakPolicy, sandboxRoot);
    }

    public @NotNull BoxedPath getRoot() {
        return new BoxedPath(this.m_fs.getSandboxAbsolutePath(), this);
    }

    public @NotNull BoxedPath of(@NotNull Path path) {
        return new BoxedPath(path, this);
    }

    public @NotNull BoxedPath of(@NotNull String first, @NotNull String... more) {
        return of(Path.of(first, more));
    }

    public @NotNull BoxedPath resolve(@NotNull Path other) {
        return getRoot().resolve(other);
    }

    public @NotNull BoxedPath resolve(@NotNull String other) {
        return resolve(Path.of(other));
    }

    // intentionally package private
    SandboxJailbreak getJailbreakPolicy() { return m_fs.getJailbreakPolicy(); }
    // intentionally package private
    BoxedFileSystem getFileSystem() { return m_fs; }
}
