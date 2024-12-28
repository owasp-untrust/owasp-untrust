package org.owasp.untrust.boxedpath;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class BoxedFileSystemProvider extends FileSystemProvider {
    private final Map<Path, BoxedFileSystem> m_filesystems = new HashMap<>(10);

    @Override
    public String getScheme() {
        return "sandbox";
    }

    @Override
    public FileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        Path sandboxAbsolutePath = extractSandboxPath(uri);
        if (m_filesystems.containsKey(sandboxAbsolutePath)) {
            throw new FileSystemAlreadyExistsException();
        }
        BoxedFileSystem newFs = new BoxedFileSystem(this, sandboxAbsolutePath);
        m_filesystems.put(sandboxAbsolutePath, newFs);
        return newFs;
    }

    private static Path extractSandboxPath(URI uri) {
        String schemeSpecificPart = uri.getSchemeSpecificPart();
        String[] sandboxedPathParts = schemeSpecificPart.split("!");
        URI nestedUri = URI.create(sandboxedPathParts[0]);
        //String internalPath = schemeSpecificPart.substring(separatorIndex + 1);
        return Paths.get(nestedUri).toAbsolutePath().normalize();
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        Path sandboxAbsolutePath = extractSandboxPath(uri);
        BoxedFileSystem fs = m_filesystems.get(sandboxAbsolutePath);
        if (fs == null) {
            throw new FileSystemNotFoundException();
        }
        return fs;
    }

    @Override
    public Path getPath(URI uri) {
        FileSystem fs = getFileSystem(uri);
        return fs.getPath(uri.getPath());
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> set, FileAttribute<?>... fileAttributes) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        return targetPath.getFileSystem().provider().newByteChannel(targetPath, set, fileAttributes);
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path path, DirectoryStream.Filter<? super Path> filter) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        return targetPath.getFileSystem().provider().newDirectoryStream(targetPath, filter);
    }

    @Override
    public void createDirectory(Path path, FileAttribute<?>... fileAttributes) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        targetPath.getFileSystem().provider().createDirectory(targetPath, fileAttributes);
    }

    @Override
    public void delete(Path path) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        targetPath.getFileSystem().provider().delete(targetPath);
    }

    @Override
    public void copy(Path path, Path path1, CopyOption... copyOptions) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        targetPath.getFileSystem().provider().copy(targetPath, path1, copyOptions);
    }

    @Override
    public void move(Path path, Path path1, CopyOption... copyOptions) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        targetPath.getFileSystem().provider().move(targetPath, path1, copyOptions);
    }

    @Override
    public boolean isSameFile(Path path, Path path1) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        return targetPath.getFileSystem().provider().isSameFile(targetPath, path1);
    }

    @Override
    public boolean isHidden(Path path) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        return targetPath.getFileSystem().provider().isHidden(targetPath);
    }

    @Override
    public FileStore getFileStore(Path path) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        return targetPath.getFileSystem().provider().getFileStore(targetPath);
    }

    @Override
    public void checkAccess(Path path, AccessMode... accessModes) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        targetPath.getFileSystem().provider().checkAccess(targetPath, accessModes);
    }

    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> aClass, LinkOption... linkOptions) {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        return targetPath.getFileSystem().provider().getFileAttributeView(targetPath, aClass, linkOptions);
    }

    @Override
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> aClass, LinkOption... linkOptions) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        return targetPath.getFileSystem().provider().readAttributes(targetPath, aClass, linkOptions);
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String s, LinkOption... linkOptions) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        return targetPath.getFileSystem().provider().readAttributes(targetPath, s, linkOptions);
    }

    @Override
    public void setAttribute(Path path, String s, Object o, LinkOption... linkOptions) throws IOException {
        Path targetPath = ((BoxedPath)path).getUnprotectedPath();
        targetPath.getFileSystem().provider().setAttribute(targetPath, s, o, linkOptions);
    }

    void removeRegisteredFileSystem(BoxedFileSystem fs) {
        BoxedFileSystem oldFs = m_filesystems.remove(fs);
        assert(oldFs != null);
    }
}
