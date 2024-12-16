# SHA-256 Hash Implementation in Kotlin

[![GitHub License](https://img.shields.io/github/license/cesp99/Sha256-Kotlin?style=flat)](https://github.com/cesp99/Sha256-Kotlin/blob/main/LICENSE) ![Kotlin Badge](https://img.shields.io/badge/Kotlin-7F52FF?logo=kotlin&logoColor=fff&style=flat)

A full Kotlin implementation of the SHA-256 hash algorithm.
Ready to be used into Kotlin Multi Platform apps.

> [!NOTE]  
> Import the file into the `Common Main` of your Kotlin Multi Platform app.
> When you import the `Sha256.kt` file, dont forget to add `package {YOUR PACKAGE NAME DIRECTORY}` on top of the file.

## Overview

This repository provides a simple and efficient implementation of the SHA-256 hash function in Kotlin. 


## Usage

Generating a SHA-256 Hash from a Byte Array to Byte Array

```kotlin
val byteArray = "Hello, World!".encodeToByteArray()
val hash = byteArray.sha256()
```

Generating a SHA-256 Hash from a String to a String

```kotlin
val string = "Hello, World!"
val hash = string.sha256String()
```

## Credits

* [@cesp99](https://github.com/cesp99)
* [@komputing](https://github.com/komputing/KHash)
* [@meyfa](https://github.com/meyfa/java-sha256)

## Contributing

Contributions are welcome! If you have any suggestions, bug reports, or improvements, please submit an issue or pull request on this repository's GitHub page.

## License

This implementation is licensed under the [AGPL 3.0 License](https://github.com/cesp99/Sha256-kotlin/blob/main/LICENSE).
