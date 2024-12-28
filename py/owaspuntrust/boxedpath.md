## BoxedPath and SandboxPath: Secure File Path Handling

#### **The Need**
In modern applications, especially those handling untrusted code or user-uploaded files, secure access to the file system is critical. Unrestricted access can lead to vulnerabilities such as:
- Accessing sensitive files outside the intended directory.
- Exploiting path traversal to manipulate or steal data.

To mitigate these risks, applications need a mechanism to enforce strict constraints on file paths, ensuring they remain within a designated secure directory or "sandbox."

---

#### **The Solution**
The `BoxedPath` and `Sandbox` classes provide a robust solution for secure file path management:
- **BoxedPath**:
  - Ensures any file path manipulation stays within a predefined sandbox directory.
  - Validates paths during initialization and every operation to prevent unauthorized access.
  - Supports common file operations like opening files, checking existence, and retrieving metadata.

- **Sandbox**:
  - A specialized form of `BoxedPath` that represents the root of a sandbox.
  - Simplifies creating a constrained environment by setting the sandbox and path to the same directory.

---

#### **Key Features**
- **Path Validation**: Ensures the real path of any file operation remains within the sandbox.
- **Path Composition**: Allows safe concatenation of path segments while maintaining constraints.
- **Common Operations**: Supports file operations like opening, checking existence, and accessing metadata within the sandbox.
- **Security Overrides**: Provides explicit methods to access real paths when necessary but warns of security implications.

---

#### **Sample Code**
Here’s an example demonstrating the use of `BoxedPath` and `Sandbox`:

```python
from boxedpath import BoxedPath, Sandbox

# Define a secure sandbox directory
sandbox = Sandbox('/secure/sandbox')

# Create a path within the sandbox
file_path = sandbox / 'example.txt'

# Check if the file exists
if file_path.exists():
    print(f"File found: {file_path}")
    # Open the file for reading
    with file_path.open('r') as f:
        content = f.read()
        print("File Content:", content)
else:
    print(f"File does not exist: {file_path}")

# Attempting to create a path outside the sandbox will raise a PermissionError
try:
    invalid_path = sandbox / '../outside.txt'
except PermissionError as e:
    print("Security Error:", e)
```

---

#### **Benefits**
- **Enhanced Security**: Restricts file operations to a designated sandbox, preventing unauthorized access.
- **Ease of Use**: Provides intuitive APIs for path manipulation and file operations.
- **Flexibility**: Handles complex path manipulations while maintaining security constraints.

These classes are essential tools for any application needing controlled access to the file system, ensuring security without compromising functionality.

### Migration from `Path` to `BoxedPath`

Migrating from Python's built-in `pathlib.Path` to `BoxedPath` involves understanding and adapting to the security constraints that `BoxedPath` enforces. While `pathlib.Path` offers a versatile API for file system path manipulation, it does not inherently enforce security boundaries. `BoxedPath`, on the other hand, ensures all operations remain within a defined sandbox for enhanced security.

---

#### **Steps for Migration**

1. **Initialization**:
   Replace `pathlib.Path` instances with `BoxedPath`. You must specify the sandbox directory as part of the `BoxedPath` initialization.

   **Before**:
   ```python
   from pathlib import Path

   path = Path('/secure/sandbox/example.txt')
   ```

   **After**:
   ```python
   from boxedpath import BoxedPath

   path = BoxedPath('/secure/sandbox/example.txt', '/secure/sandbox')
   ```

---

2. **Path Joining**:
   Use `/` for joining paths, which is consistent with `pathlib.Path`. Ensure that all resulting paths stay within the sandbox.

   **Before**:
   ```python
   path = Path('/secure/sandbox') / 'example.txt'
   ```

   **After**:
   ```python
   sandbox = Sandbox('/secure/sandbox')  # shorthand for BoxedPath('/secure/sandbox', '/secure/sandbox')
   path = sandbox / 'example.txt'
   ```

---

3. **Validation**:
   Paths outside the sandbox are automatically blocked. This is a significant change from `pathlib.Path`, which allows unrestricted path traversal.

   **Before**:
   ```python
   path = Path('/secure/sandbox') / '../outside.txt'  # No validation
   print(path.resolve())  # This resolves to a path outside the sandbox
   ```

   **After**:
   ```python
   try:
       path = sandbox / '../outside.txt'  # Raises PermissionError
   except PermissionError as e:
       print(f"Security Error: {e}")
   ```

---

4. **Common File Operations**:
   Operations like opening a file, checking if it exists, or retrieving metadata work similarly but are constrained by the sandbox.

   **Before**:
   ```python
   with path.open('r') as file:
       content = file.read()

   exists = path.exists()
   stats = path.stat()
   ```

   **After**:
   ```python
   with path.open('r') as file:
       content = file.read()

   exists = path.exists()
   stats = path.stat()
   ```

---

5. **Real Path Access**:
   If your application requires access to the real (absolute) path, use `BoxedPath.insecure_unrestrained_realpath()` cautiously. This bypasses sandbox constraints and should only be used in trusted scenarios.

   **Before**:
   ```python
   real_path = path.resolve()
   ```

   **After**:
   ```python
   real_path = path.insecure_unrestrained_realpath()
   ```

---

#### **Benefits of Migration**
- **Security First**: Automatically prevents directory traversal and access to unintended parts of the file system.
- **Minimal Changes**: Retains the familiar API of `pathlib.Path`, easing the transition.
- **Controlled Operations**: Enforces path validation at every operation, reducing potential vulnerabilities.

---

#### **Migration Example**

**Original Code Using `pathlib.Path`**:
```python
from pathlib import Path

base_path = Path('/secure/sandbox')
file_path = base_path / 'example.txt'

if file_path.exists():
    with file_path.open('r') as f:
        print(f.read())
```

**Updated Code Using `BoxedPath`**:
```python
from boxedpath import BoxedPath

sandbox = BoxedPath('/secure/sandbox', '/secure/sandbox')
file_path = sandbox / 'example.txt'

if file_path.exists():
    with file_path.open('r') as f:
        print(f.read())
```

This structured migration ensures the application benefits from the enhanced security provided by `BoxedPath` without significant code rewrites.
