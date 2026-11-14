# 凭据检测中的类型声明（0.1.6）

`security.credentials` 区分显式 `var`、`let`、`const` 变量声明中的已知类型与赋值。支持常见 Swift/TypeScript 简单类型，包括 Bool、String、Foundation.Data、boolean、string、number，以及可选/数组类型和 `| null`。仅消除类型注解造成的误报，并识别匹配类型的布尔、空值和空构造器初始化。不是完整语法解析器，其他声明形式、复杂类型和动态初始化仍可能保守阻断。

例如 `public var secret: Bool = false` 和 `const token: string;` 通过；`let password: String = "SYNTHETIC_PASSWORD"`、`const token: string = "SYNTHETIC_TOKEN"` 仍阻断。不会豁免整个文件、整行或整份结果；旁边的凭据、IP、设备标识继续检测。

结构化数据的字段值不享受类型声明豁免：`{"password":"String"}`、`{"secret":"Bool"}` 仍按凭据处理。支持 password/passwd、token/access_token/refresh_token、api_key、client_secret、secret 和 authorization 等字段，包括所支持的驼峰/分隔符形式。私钥头和带密码 URL 继续检测。

凭据字段仍采用至少四个非空白字符的启发式，不保证识别无字段标签的任意 Token、任意编码或动态拼接的秘密。不要把本次修复理解为所有代码均会放行，或所有可能的秘密都已被覆盖。
