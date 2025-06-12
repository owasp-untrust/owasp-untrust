package org.owasp.untrust.boxedpath;

import javax.validation.constraints.NotNull;

import java.net.URI;
import java.io.IOException;
import java.nio.file.*;
import java.util.Iterator;
import java.util.Optional;

public class BoxedPath implements Path {
    public static @NotNull BoxedPath of(@NotNull PathSandbox sandboxRoot, @NotNull Path path) {
        return new BoxedPath(sandboxRoot.resolve(path).getUnprotectedPath(), sandboxRoot);
    }

    public static @NotNull BoxedPath of(@NotNull PathSandbox sandboxRoot, String first, @NotNull String... more) {
        return of(sandboxRoot, Path.of(first, more));
    }

    public static @NotNull URI toUri(@NotNull Path sandbox) {
        return toUriWithAbsoluteSandbox(SandboxJailbreak.DISALLOW, sandbox.toAbsolutePath().normalize(), Optional.empty());
    }

    public static @NotNull URI toUri(@NotNull Path sandbox, @NotNull Path path) {
        return toUriWithAbsoluteSandbox(SandboxJailbreak.DISALLOW, sandbox.toAbsolutePath().normalize(), Optional.of(path));
    }

    public static @NotNull URI toUri(SandboxJailbreak jailbreakPolicy, @NotNull Path sandbox) {
        return toUriWithAbsoluteSandbox(jailbreakPolicy, sandbox.toAbsolutePath().normalize(), Optional.empty());
    }

    public static @NotNull URI toUri(SandboxJailbreak jailbreakPolicy, @NotNull Path sandbox, @NotNull Path path) {
        return toUriWithAbsoluteSandbox(jailbreakPolicy, sandbox.toAbsolutePath().normalize(), Optional.of(path));
    }

    private static @NotNull URI toUriWithAbsoluteSandbox(SandboxJailbreak jailbreakPolicy, @NotNull Path sandboxAbsolute, @NotNull Optional<Path> path) {
        URI sandboxRootUri = sandboxAbsolute.toUri();
        String uriString = "sandbox:" + sandboxRootUri;

        if (path.isPresent()) {
            String encodedFilePath = path.toString().replace("\\", "/");
            uriString += "!" + encodedFilePath;
        }

        if (jailbreakPolicy == SandboxJailbreak.UNCHECKED_SYMLINKS) {
            uriString += "#UNCHECKED_SYMLINKS";
        }
    
        return URI.create(uriString);
    }

    private final @NotNull Path m_path;
    private final @NotNull BoxedFileSystem m_sandboxFs;

    // Constructor validates that the path is within the sandbox
    protected BoxedPath(@NotNull Path path, @NotNull BoxedFileSystem sandboxFs) {
        this.m_sandboxFs = sandboxFs; // sandboxRoot.toAbsolutePath().normalize();
        validateWithinSandbox(sandboxFs.getJailbreakPolicy(), path, sandboxFs.getSandboxAbsolutePath());
        this.m_path = path;
    }

    protected BoxedPath(@NotNull Path path, @NotNull PathSandbox sandboxRoot) {
        this(path, sandboxRoot.getFileSystem());
    }

    // Validates if the path is within the sandbox
    private static void validateWithinSandbox(SandboxJailbreak jailbreakPolicy, @NotNull Path candidatePath, @NotNull Path sandboxAbsolute) {
        Path absolutePath = candidatePath.toAbsolutePath().normalize();
        if (!absolutePath.startsWith(sandboxAbsolute)) {
            throw new SecurityException("Path " + candidatePath + " is outside the sandbox " + sandboxAbsolute);
        }

        if (jailbreakPolicy == SandboxJailbreak.DISALLOW) {
            try {
                // traverse name parts and turn into real names
                Path realSandbox = sandboxAbsolute.toRealPath();

                Path relativePart = sandboxAbsolute.relativize(absolutePath);
                Path realPathPrefix = realSandbox;
                try {
                    for (int i = 0 ; i < relativePart.getNameCount() ; ++i) {
                        realPathPrefix = realPathPrefix.resolve(relativePart.getName(i)).toRealPath();
                    }
                }
                catch (IOException ex) {
                    // adding path part results in path that doesn't exist on file system, so all path parts from here on are not symlinks
                }
                // ensure path part that DOES exist on file system is within sandbox
                if (!realPathPrefix.startsWith(realSandbox)) {
                    throw new SecurityException("Path " + candidatePath + " is outside the sandbox " + sandboxAbsolute + " [after resolving symlinks]");
                }
            }
            catch (IOException ex) {
                // even sandbox path doesn't exist on file system, so it couldn't have a symlink within it... ==> All ok!
            }
        }
    }

    // Overridden resolve method to join paths while enforcing the sandbox
    @Override
    public @NotNull BoxedPath resolve(@NotNull Path other) {
        return new BoxedPath(this.m_path.resolve(other), m_sandboxFs);
    }
    
    public @NotNull BoxedPath resolve(@NotNull BoxedPath other) {
        throw new IllegalArgumentException("Cannot resolve a BoxedPath from a BoxedPath - they both have a sandbox absolute prefix");
    }

    @Override
    public @NotNull BoxedPath resolve(@NotNull String other) {
        return resolve(Path.of(other));
    }

    @Override
    public @NotNull BoxedPath resolveSibling(@NotNull Path other) {
        return new BoxedPath(this.m_path.resolveSibling(other), m_sandboxFs);
    }

    public @NotNull BoxedPath resolveSibling(@NotNull BoxedPath other) {
        throw new IllegalArgumentException("Cannot resolve a BoxedPath from a BoxedPath - they both have a sandbox absolute prefix");
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
        throw new SecurityException("relativization of paths does not work with sandboxing, as all paths must be relative to the sandbox");
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

    public Path unprotectedRelativeToSandbox() {
        Path absolutePath = m_path.toAbsolutePath().normalize();
        return m_sandboxFs.getSandboxAbsolutePath().relativize(absolutePath);
    }

    @Override
    public boolean startsWith(Path other) {
        return this.m_path.startsWith(other);
    }

    public boolean startsWith(BoxedPath other) {
        return this.m_path.startsWith(other.m_path);
    }
    
    @Override
    public boolean startsWith(String other) {
        return this.m_path.startsWith(other);
    }

    @Override
    public boolean endsWith(Path other) {
        return this.m_path.endsWith(other);
    }

    public boolean endsWith(BoxedPath other) {
        return this.m_path.startsWith(other.m_path);
    }
    
    @Override
    public boolean endsWith(String other) {
        return this.m_path.endsWith(other);
    }

    @Override
    public BoxedPath subpath(int beginIndex, int endIndex) {
        Path pathAbsolute = this.m_path.isAbsolute() ? this.m_path : this.m_path.toAbsolutePath();
        int sandboxNamesCount = this.m_sandboxFs.getSandboxAbsolutePath().getNameCount();
        return new BoxedPath(this.m_sandboxFs.getSandboxAbsolutePath().resolve(pathAbsolute.subpath(beginIndex + sandboxNamesCount, endIndex + sandboxNamesCount)), m_sandboxFs);
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
    
    public int compareTo(BoxedPath other) {
        return this.m_path.compareTo(other.m_path);
    }

    @Override
    public String toString() {
        return this.m_path.toString();
    }

    @Override
    public @NotNull URI toUri() {
        return toUriWithAbsoluteSandbox(m_sandboxFs.getJailbreakPolicy(), m_sandboxFs.getSandboxAbsolutePath(), Optional.of(m_path));
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
