package org.owasp.untrust.boxedpath;

import javax.validation.constraints.NotNull;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.spi.FileSystemProvider;
import java.util.Set;
//import java.util.concurrent.atomic.AtomicLong;

class BoxedFileSystem extends FileSystem {
    private final @NotNull BoxedFileSystemProvider m_provider;
    private final @NotNull Path m_sandboxAbsolute;
    private final SandboxJailbreak m_jailbreakPolicy;
    //private final @NotNull AtomicLong m_refCount = new AtomicLong(1);

    public BoxedFileSystem(BoxedFileSystemProvider provider, Path sandboxAbsolute, SandboxJailbreak jailbreakPolicy) {
        this.m_provider = provider;
        this.m_sandboxAbsolute = sandboxAbsolute;
        this.m_jailbreakPolicy = jailbreakPolicy;
    }

    // intentionally package private
    Path getSandboxAbsolutePath() { return m_sandboxAbsolute; }
    // intentionally package private
    SandboxJailbreak getJailbreakPolicy() { return m_jailbreakPolicy; }

    @Override
    public FileSystemProvider provider() {
        return m_provider;
    }

    @Override
    public @NotNull Path getPath(@NotNull String first, String... more) {
        return new BoxedPath(m_sandboxAbsolute.getFileSystem().getPath(first, more), this);
    }

    @Override
    public @NotNull PathMatcher getPathMatcher(@NotNull String s) {
        return m_sandboxAbsolute.getFileSystem().getPathMatcher(s);
    }

    @Override
    public UserPrincipalLookupService getUserPrincipalLookupService() {
        return m_sandboxAbsolute.getFileSystem().getUserPrincipalLookupService();
    }

    @Override
    public WatchService newWatchService() throws IOException {
        return m_sandboxAbsolute.getFileSystem().newWatchService();
    }

    /*void incRefcount() {
        long oldCount = m_refCount.getAndIncrement();
        assert(oldCount > 0);
    }*/

    // TODO: Figure out when to removeRegisteredFileSystem, if ever 
    @Override
    public void close() throws IOException {
        /*long newCount = m_refCount.decrementAndGet();
        if (newCount == 0) {
            m_provider.removeRegisteredFileSystem(this);
        }*/
    }

    @Override
    public boolean isOpen() {
        return m_sandboxAbsolute.getFileSystem().isOpen();
    }

    @Override
    public boolean isReadOnly() {
        return m_sandboxAbsolute.getFileSystem().isReadOnly();
    }

    @Override
    public String getSeparator() {
        return m_sandboxAbsolute.getFileSystem().getSeparator();
    }

    @Override
    public Iterable<Path> getRootDirectories() {
        return m_sandboxAbsolute.getFileSystem().getRootDirectories();
    }

    @Override
    public Iterable<FileStore> getFileStores() {
        return m_sandboxAbsolute.getFileSystem().getFileStores();
    }

    @Override
    public Set<String> supportedFileAttributeViews() {
        return m_sandboxAbsolute.getFileSystem().supportedFileAttributeViews();
    }
}
