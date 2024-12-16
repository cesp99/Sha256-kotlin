// put here your "package com.example etc."

object Sha256 {

    private val K = intArrayOf(
        0x428a2f98, 0x71374491, -0x4a3f0431, -0x164a245b, 0x3956c25b, 0x59f111f1, -0x6dc07d5c, -0x54e3a12b,
        -0x27f85568, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, -0x7f214e02, -0x6423f959, -0x3e640e8c,
        -0x1b64963f, -0x1041b87a, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        -0x67c1aeae, -0x57ce3993, -0x4ffcd838, -0x40a68039, -0x391ff40d, -0x2a586eb9, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, -0x7e3d36d2, -0x6d8dd37b,
        -0x5d40175f, -0x57e599b5, -0x3db47490, -0x3893ae5d, -0x2e6d17e7, -0x2966f9dc, -0xbf1ca7b, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, -0x7b3787ec, -0x7338fdf8, -0x6f410006, -0x5baf9315, -0x41065c09, -0x398e870e
    )

    private val H0 = intArrayOf(
        0x6a09e667, -0x4498517b, 0x3c6ef372, -0x5ab00ac6,
        0x510e527f, -0x64fa9774, 0x1f83d9ab, 0x5be0cd19
    )

    // Working arrays
    private val W = IntArray(64)
    private val H = IntArray(8)
    private val TEMP = IntArray(8)

    // Main function to generate Sha256 hash from byte arrays
    // returns The digest's bytes.

    fun digest(message: ByteArray): ByteArray {
        // Let H = H0
        H0.copy(0,
            H, 0, H0.size)

        // Initialize all words
        val words = padMessage(message).toIntArray()

        // Enumerate all blocks (each containing 16 words)
        var i = 0
        val n = words.size / 16
        while (i < n) {

            // initialize W from the block's words
            words.copy(i * 16, W, 0, 16)
            for (t in 16 until W.size) {
                W[t] = (smallSig1(W[t - 2]) + W[t - 7] + smallSig0(
                    W[t - 15]
                ) + W[t - 16])
            }

            // Let TEMP = H
            H.copy(0,
                TEMP, 0, H.size)

            // Operate on TEMP
            for (t in W.indices) {
                val t1 = (TEMP[7] + bigSig1(TEMP[4]) + ch(
                    TEMP[4],
                    TEMP[5],
                    TEMP[6]
                ) + K[t] + W[t])
                val t2 = bigSig0(TEMP[0]) + maj(
                    TEMP[0],
                    TEMP[1],
                    TEMP[2]
                )
                TEMP.copy(0,
                    TEMP, 1, TEMP.size - 1)
                TEMP[4] += t1
                TEMP[0] = t1 + t2
            }

            // Add values in TEMP to values in H
            for (t in H.indices) {
                H[t] += TEMP[t]
            }

            ++i
        }

        return H.toByteArray()
    }

    // Pads the input according to the Sha256 rules
    // returns the padded message's bytes

    private fun padMessage(message: ByteArray): ByteArray {
        val blockBits = 512
        val blockBytes = blockBits / 8

        // Calculate padding length
        var newMessageLength = message.size + 1 + 8 // original + 1-bit + 8-byte length
        val padBytes = blockBytes - newMessageLength % blockBytes
        newMessageLength += padBytes

        // Create padded message array
        val paddedMessage = ByteArray(newMessageLength)
        message.copyInto(paddedMessage, 0, 0, message.size)

        // Add 1-bit (0x80)
        paddedMessage[message.size] = 0x80.toByte()

        // Add message length as 64-bit integer (big-endian)
        val messageLengthBits = message.size * 8L
        for (i in 0..7) {
            paddedMessage[newMessageLength - 8 + i] = (messageLengthBits shr (56 - i * 8)).toByte()
        }

        return paddedMessage
    }

    // Hyperbolic cosine
    private fun ch(x: Int, y: Int, z: Int): Int {
        return x and y or (x.inv() and z)
    }

    // Majority function 
    private fun maj(x: Int, y: Int, z: Int): Int {
        return x and y or (x and z) or (y and z)
    }

    private fun bigSig0(x: Int): Int {
        return (x.rotateRight(2) xor x.rotateRight(13) xor x.rotateRight(22))
    }

    private fun bigSig1(x: Int): Int {
        return (x.rotateRight(6) xor x.rotateRight(11) xor x.rotateRight(25))
    }

    private fun smallSig0(x: Int): Int {
        return (x.rotateRight(7) xor x.rotateRight(18) xor x.ushr(3))
    }

    private fun smallSig1(x: Int): Int {
        return (x.rotateRight(17) xor x.rotateRight(19) xor x.ushr(10))
    }
}


/**
 * Utils for the calculation
 */

// Returns the SHA256 digest of this byte array.
fun ByteArray.sha256(): ByteArray = Sha256.digest(this)



// Returns the SHA256 digest of this string.
fun String.sha256Bytes(): ByteArray = this.encodeToByteArray().sha256() // To Byte Array

fun String.sha256String(): String = this.encodeToByteArray().sha256().toHex() // To hex string



internal fun Byte.toUInt() = when {
    (toInt() < 0) -> 255 + toInt() + 1
    else -> toInt()
}

internal fun Int.rotateRight(distance: Int): Int {
    return this.ushr(distance) or (this shl -distance)
}



// Converts an int to an array of bytes. (4 bytes)
internal fun Int.toBytes(): Array<Byte> {
    val result = ByteArray(4)
    result[0] = (this shr 24).toByte()
    result[1] = (this shr 16).toByte()
    result[2] = (this shr 8).toByte()
    result[3] = this.toByte()
    return result.toTypedArray()
}



// Converts an IntArray to a byte array, each int is represented as (4 bytes), throws an error of the array size isn't a multiple of 4.
internal fun IntArray.toByteArray(): ByteArray {
    require(this.size % 4 == 0) { "Array size must be a multiple of 4" }

    val array = ByteArray(this.size * 4)
    for (i in this.indices) {
        array[i * 4] = (this[i] shr 24).toByte()
        array[i * 4 + 1] = (this[i] shr 16).toByte()
        array[i * 4 + 2] = (this[i] shr 8).toByte()
        array[i * 4 + 3] = this[i].toByte()
    }
    return array
}



// Copies an array from the specified source array, beginning at the specified position (srcPos), to the specified position (destPos) of the destination array (dest).
internal fun IntArray.copy(srcPos: Int, dest: IntArray, destPos: Int, length: Int) {
    this.copyInto(dest, destPos, srcPos, srcPos + length)
}



// Writes a long split into 8 bytes.
internal fun ByteArray.putLong(offset: Int, value: Long) {
    for (i in 7 downTo 0) {
        val temp = (value ushr (i * 8)).toUByte()
        this[offset + 7 - i] = temp.toByte()
    }
}



// Converts a byte array into an int array, throws an error if the array size isn't a multiple of 4.
internal fun ByteArray.toIntArray(): IntArray {
    if (this.size % 4 != 0) {
        throw IllegalArgumentException("Byte array length must be a multiple of 4")
    }

    val array = IntArray(this.size / 4)
    for (i in array.indices) {
        array[i] = (this[i * 4].toInt() and 0xFF shl 24) or
                (this[i * 4 + 1].toInt() and 0xFF shl 16) or
                (this[i * 4 + 2].toInt() and 0xFF shl 8) or
                (this[i * 4 + 3].toInt() and 0xFF)
    }
    return array
}

/**
 * Copies an array from the specified source array, beginning at the
 * specified position, to the specified position of the destination array.
 */
internal fun ByteArray.copy(srcPos: Int, dest: ByteArray, destPos: Int, length: Int) {
    this.copyInto(dest, destPos, srcPos, srcPos + length)
}



/**
 * Converts the first 4 bytes into their integer representation following the big-endian conversion.
 * @throws NumberFormatException if the array size is less than 4
 */
internal fun Array<Byte>.toInt(): Int {
    if (this.size < 4) throw NumberFormatException("The array size is less than 4")
    return (this[0].toUInt() shl 24) + (this[1].toUInt() shl 16) + (this[2].toUInt() shl 8) + (this[3].toUInt() shl 0)
}



/**
 * Convert the Sha256 hash's bytes into the actual string hash in hex
 */
fun ByteArray.toHex(): String {
    return joinToString(separator = "") { eachByte ->
        eachByte.toInt().and(0xFF).toString(16).padStart(2, '0')
    }
}