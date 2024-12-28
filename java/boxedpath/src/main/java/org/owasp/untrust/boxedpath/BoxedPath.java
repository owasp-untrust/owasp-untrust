package org.owasp.untrust.boxedpath;

import javax.validation.constraints.NotNull;
import java.net.URI;
import java.nio.file.Path;

import java.io.IOException;
import java.nio.file.*;
import java.util.Iterator;
import java.util.Optional;

public class BoxedPath implements Path {
    public static @NotNull BoxedPath of(@NotNull SandboxPath sandboxRoot, @NotNull Path path) {
        return new BoxedPath(path, sandboxRoot);
    }

    public static @NotNull BoxedPath of(@NotNull SandboxPath sandboxRoot, String first, @NotNull String... more) {
        return new BoxedPath(Path.of(first, more), sandboxRoot);
    }

    public static @NotNull URI toUri(@NotNull Path sandbox) {
        return toUriWithAbsoluteSandbox(sandbox.toAbsolutePath().normalize(), Optional.empty());
    }

    public static @NotNull URI toUri(@NotNull Path sandbox, @NotNull Path path) {
        return toUriWithAbsoluteSandbox(sandbox.toAbsolutePath().normalize(), Optional.of(path));
    }

    public static @NotNull URI toUriWithAbsoluteSandbox(@NotNull Path sandboxAbsolute, @NotNull Optional<Path> path) {
        URI sandboxRootUri = sandboxAbsolute.toUri();
        String uriString = "sandbox:" + sandboxRootUri;
        if (path.isPresent()) {
            String encodedFilePath = path.toString().replace("\\", "/");
            uriString += "!" + encodedFilePath;
        }
        return URI.create(uriString);
    }

    private final @NotNull Path m_path;
    private final @NotNull BoxedFileSystem m_sandboxFs;

    // Constructor validates that the path is within the sandbox
    protected BoxedPath(@NotNull Path path, @NotNull BoxedFileSystem sandboxFs) {
        this.m_sandboxFs = sandboxFs; // sandboxRoot.toAbsolutePath().normalize();
        validateWithinSandbox(path, sandboxFs.getSandboxAbsolutePath());
        this.m_path = path;
    }

    protected BoxedPath(@NotNull Path path, @NotNull SandboxPath sandboxRoot) {
        this(path, sandboxRoot.getFileSystem());
    }

    // Validates if the path is within the sandbox
    private static void validateWithinSandbox(@NotNull Path candidatePath, @NotNull Path sandboxAbsolute) {
        Path absolutePath = candidatePath.toAbsolutePath().normalize();
        if (!absolutePath.startsWith(sandboxAbsolute)) {
            throw new SecurityException("Path " + candidatePath + " is outside the sandbox " + sandboxAbsolute);
        }
    }

    // Overridden resolve method to join paths while enforcing the sandbox
    @Override
    public @NotNull BoxedPath resolve(@NotNull Path other) {
        return new BoxedPath(this.m_path.resolve(other), m_sandboxFs);
    }

    @Override
    public @NotNull BoxedPath resolve(@NotNull String other) {
        return resolve(Path.of(other));
    }

    @Override
    public @NotNull BoxedPath resolveSibling(@NotNull Path other) {
        return new BoxedPath(this.m_path.resolveSibling(other), m_sandboxFs);
    }

    @Override
    public @NotNull BoxedPath resolveSibling(@NotNull String other) {
        return resolveSibling(Path.of(other));
    }

    @Override
    public @NotNull BoxedPath normalize() {
        return new BoxedPath(this.m_path.normalize(), m_sandboxFs);
    }

    @Override
    public @NotNull BoxedPath relativize(Path other) {
        return new BoxedPath(this.m_path.relativize(other), m_sandboxFs);
    }

    @Override
    public Path getFileName() {
        return this.m_path.getFileName();
    }

    @Override
    public BoxedPath getParent() {
        return new BoxedPath(this.m_path.getParent(), m_sandboxFs);
    }

    @Override
    public Path getRoot() {
        return this.m_path.getRoot();
    }

    @Override
    public int getNameCount() {
        return this.m_path.getNameCount();
    }

    @Override
    public Path getName(int index) {
        return this.m_path.getName(index);
    }

    public Path relativeToSandbox() {
        Path absolutePath = m_path.toAbsolutePath().normalize();
        return m_sandboxFs.getSandboxAbsolutePath().relativize(absolutePath);
    }

    @Override
    public boolean startsWith(Path other) {
        return this.m_path.startsWith(other);
    }

    @Override
    public boolean startsWith(String other) {
        return this.m_path.startsWith(other);
    }

    @Override
    public boolean endsWith(Path other) {
        return this.m_path.endsWith(other);
    }

    @Override
    public boolean endsWith(String other) {
        return this.m_path.endsWith(other);
    }

    @Override
    public BoxedPath subpath(int beginIndex, int endIndex) {
        return new BoxedPath(this.m_path.subpath(beginIndex, endIndex), m_sandboxFs);
    }

    @Override
    public boolean isAbsolute() {
        return this.m_path.isAbsolute();
    }

    @Override
    public BoxedPath toAbsolutePath() {
        return new BoxedPath(this.m_path.toAbsolutePath(), m_sandboxFs);
    }

    @Override
    public BoxedPath toRealPath(LinkOption... options) throws IOException {
        return new BoxedPath(this.m_path.toRealPath(options), m_sandboxFs);
    }

    @Override
    public Iterator<Path> iterator() {
        return this.m_path.iterator();
    }

    @Override
    public int compareTo(Path other) {
        return this.m_path.compareTo(other);
    }

    @Override
    public String toString() {
        return this.m_path.toString();
    }

    @Override
    public @NotNull URI toUri() {
        return toUriWithAbsoluteSandbox(m_sandboxFs.getSandboxAbsolutePath(), Optional.of(m_path));
    }

    @Override
    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>... events) throws IOException {
        return this.m_path.register(watcher, events);
    }

    @Override
    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>[] events, WatchEvent.Modifier... modifiers)
            throws IOException {
        return this.m_path.register(watcher, events, modifiers);
    }

    @Override
    public FileSystem getFileSystem() {
        return this.m_sandboxFs;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof BoxedPath)) return false;
        BoxedPath other = (BoxedPath) obj;
        return this.m_path.equals(other.m_path) && this.m_sandboxFs.getSandboxAbsolutePath().equals(other.m_sandboxFs.getSandboxAbsolutePath());
    }

    @Override
    public int hashCode() {
        return this.m_path.hashCode();
    }

    Path getUnprotectedPath() { return m_path; }
    Path getUnprotectedAbsoluteSandbox() { return m_sandboxFs.getSandboxAbsolutePath(); }
}
