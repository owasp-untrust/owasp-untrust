---

layout: col-sidebar
title: OWASP untrust
tags: example-tag
level: 2
type: code
pitch: OWASP-Untrust replaces risky base programming constructs with secure, validated types (e.g., BoxedPath, BoundedString) to enforce safety and prevent vulnerabilities at the core.

---

### Secure, Base-Level, Programming Constructs with OWASP-Untrust

#### **The Problem with Traditional Libraries**
Traditional programming libraries, while powerful, were not designed with modern security considerations. They rely on outdated assumptions:
- The executing code and compiled binaries can be trusted.
- System-level permissions (e.g., root or su) ensure safety.
- Operating systems enforce user-level safety.

These assumptions fail in server environments:
- **Untrusted Users**: Servers expose code to malicious actors.
- **Powerful Contexts**: Servers often run with elevated privileges (e.g., root), increasing potential damage.
- **Missing Authorization**: The operating system does not inherently manage user-level permissions or authorization for server users.

---

#### **The OWASP-Untrust Vision**
To bridge the gap between traditional base-level constructs and secure task-oriented constructs, OWASP-Untrust proposes a paradigm shift. This involves creating **bounded, validated types** that enforce security policies at the language level, ensuring safe usage patterns.

---

#### **From Base Constructs to Secure Constructs**
OWASP-Untrust will provide secure alternatives to commonly misused or risky programming constructs. The core idea is to replace unbounded, permissive types with restricted, secure types that validate their content at creation.

| **Classic Type**          | **Secure Alternative**     | **Example Use Case**                             |
|----------------------------|----------------------------|-------------------------------------------------|
| `Path`                    | `BoxedPath`               | Secure file system operations confined to a sandbox. |
| `String`                  | `BoundedString`           | Strings with length and content restrictions.    |
| `int` or `Integer`        | `BoundedInteger`          | Integer values bounded by a safe range.          |
| `File Name` (`String`)    | `Filename`                | Validates acceptable characters for file names.  |
| `String` (free text)      | `FreeText`                | Ensures safe characters for freeform text.       |
| `String` (user input)     | `UserName`                | Enforces length and character restrictions.      |

---

### Secure Constructs in Action

#### **1. BoxedPath**
Classic `Path` assumes full system access, whereas `BoxedPath` confines operations to a sandbox.
```java
// Classic Path
Path unrestrictedPath = Path.of("/sensitive/system/file.txt");

// Secure BoxedPath
SandboxPath sandbox = SandboxPath.boxroot("/sandbox/root");
BoxedPath securePath = sandbox.of("file.txt");
```
Any attempt to escape the sandbox with `BoxedPath` results in a `SecurityException`.

---

#### **2. FreeText**
Classic strings allow any content, which can introduce injection vulnerabilities. `FreeText` restricts input to safe characters and enforces length constraints.

**Example: Task Descriptions**
```java
// Classic String
String taskDescription = "Execute this task!\n<script>alert(1);</script>";

// Secure FreeText
TaskDescription description = new TaskDescription("Execute this task!");
```
Attempts to include unsafe characters like `<script>` or excessive lengths are rejected at creation.

---

#### **3. Filename**
Classic filenames lack validation, leading to vulnerabilities with unsafe characters or malformed names. `Filename` enforces allowed characters and length constraints.

```java
// Classic Filename
String filename = "../../../../etc/passwd";

// Secure Filename
Filename secureFilename = new Filename("user-data.txt");
```
If the filename contains invalid characters (e.g., `/`), a `TypeValidationException` is thrown.

---

#### **4. Bounded Integer**
Unbounded integers can lead to overflows or logical errors. `Times` ensures integer values remain within a valid range.

```java
// Classic Integer
int times = -5; // Invalid value

// Secure Bounded Integer
Times validTimes = Times.from(10); // Enforces range [1, 100]
```
Values outside the defined range trigger a `TypeValidationException`.

---

### Advantages of OWASP-Untrust Constructs
1. **Validation at Creation**: Unsafe data never enters the application logic.
2. **Encapsulation of Constraints**: Security policies are enforced in reusable classes.
3. **Minimal Code Changes**: Replacing classic constructs with secure equivalents requires minimal changes while drastically improving safety.
4. **Self-Documenting Code**: Developers can understand constraints directly from type names (e.g., `FreeText`, `Filename`).

---

### A Holistic Approach to Secure Programming
OWASP-Untrust's goal is to systematically replace risky constructs across all domains:
- **File System Operations**: Use `BoxedPath` for safe and confined file access.
- **User Input Handling**: Replace unvalidated strings with bounded types (`UserName`, `TaskName`, `CommentText`).
- **Freeform Text**: Use `FreeText` to ensure safe and expected content.
- **Numerical Values**: Enforce limits with bounded integers (`Times`, `BoundedInteger`).

By adopting OWASP-Untrust, developers gain tools to create inherently secure applications, protecting against common classes of vulnerabilities at the core of the programming model.
