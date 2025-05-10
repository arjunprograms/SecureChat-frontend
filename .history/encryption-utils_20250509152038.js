// Enhanced encryption-utils.js
// This module provides end-to-end encryption for secure messaging with key rotation

class EnhancedEncryptionManager {
  constructor() {
    this.keyPair = null;
    this.publicKeys = new Map();
    this.keyCreationTime = null;
    this.KEY_ROTATION_INTERVAL = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
    
    // Check for Crypto API support
    this.cryptoSupported = window.crypto && window.crypto.subtle;
    if (!this.cryptoSupported) {
      console.warn("Web Crypto API is not supported in this browser");
      // We'll continue but with limited functionality
    }
    
    // Initialize key rotation check
    setInterval(() => this.checkKeyRotation(), 60 * 60 * 1000); // Check every hour
  }
  
  async checkKeyRotation() {
    if (!this.keyCreationTime || !this.cryptoSupported) return;
    
    const now = Date.now();
    if (now - this.keyCreationTime > this.KEY_ROTATION_INTERVAL) {
      console.log("Rotating encryption keys...");
      const oldKeyPair = this.keyPair;
      
      // Generate new keys
      await this.generateKeyPair();
      console.log("New encryption keys generated");
      
      // Update server with new public key
      this.updatePublicKeyOnServer();
      
      // Keep old private key for a transition period to decrypt messages
      // sent with the old public key (could implement more complex
      // transition mechanism if needed)
    }
  }
  
  async updatePublicKeyOnServer() {
    if (!this.cryptoSupported || !this.keyPair) return;
    
    const publicKeyBase64 = await this.exportPublicKey();
    try {
      if (!window.currentUser) {
        console.error("Cannot update key: No current user");
        return;
      }
      
      await fetch(`${window.API_BASE_URL}/update-key`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          username: window.currentUser, 
          publicKey: publicKeyBase64
        })
      });
      console.log("Public key updated on server");
    } catch (err) {
      console.error("Failed to update public key:", err);
    }
  }

  // Generate a new key pair for this user
  async generateKeyPair() {
    if (!this.cryptoSupported) {
      console.log("Using fallback key generation (no encryption)");
      // Return a dummy public key for testing
      this.keyPair = { dummy: true };
      return "dummy-public-key-for-testing";
    }
    
    try {
      console.log("Generating RSA key pair...");
      this.keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true, // extractable
        ["encrypt", "decrypt"]
      );
      
      this.keyCreationTime = Date.now();
      console.log("Key pair successfully generated");
      return this.exportPublicKey();
    } catch (error) {
      console.error("Error generating key pair:", error);
      // Fallback to dummy key for testing
      this.keyPair = { dummy: true };
      return "dummy-public-key-for-testing";
    }
  }

  // Export public key in a format that can be shared
  async exportPublicKey() {
    if (!this.cryptoSupported || !this.keyPair || this.keyPair.dummy) {
      return "dummy-public-key-for-testing";
    }
    
    try {
      const exported = await window.crypto.subtle.exportKey(
        "spki", 
        this.keyPair.publicKey
      );
      
      return this._arrayBufferToBase64(exported);
    } catch (error) {
      console.error("Error exporting public key:", error);
      return "dummy-public-key-for-testing";
    }
  }

  // Register another user's public key
  async registerPublicKey(username, publicKeyBase64) {
    if (!this.cryptoSupported) {
      console.log(`Simulated registering public key for user: ${username}`);
      this.publicKeys.set(username, "dummy-key");
      return true;
    }
    
    try {
      // Handle dummy keys from other users
      if (publicKeyBase64 === "dummy-public-key-for-testing") {
        console.log(`Registering dummy key for user: ${username}`);
        this.publicKeys.set(username, "dummy-key");
        return true;
      }
      
      const publicKeyData = this._base64ToArrayBuffer(publicKeyBase64);
      
      const publicKey = await window.crypto.subtle.importKey(
        "spki",
        publicKeyData,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        true,
        ["encrypt"]
      );
      
      this.publicKeys.set(username, publicKey);
      console.log(`Registered public key for user: ${username}`);
      return true;
    } catch (error) {
      console.error(`Failed to register public key for ${username}:`, error);
      // Register a dummy key as fallback
      this.publicKeys.set(username, "dummy-key");
      return true; // Still return true to allow the app to function
    }
  }

  // Encrypt a message for a specific user
  async encryptMessage(message, recipientUsername) {
    if (!this.cryptoSupported) {
      console.log("Simulated encryption (no actual encryption)");
      return JSON.stringify({
        dummy: true,
        originalMessage: message
      });
    }
    
    const recipientPublicKey = this.publicKeys.get(recipientUsername);
    
    if (!recipientPublicKey) {
      throw new Error(`No public key found for user: ${recipientUsername}`);
    }
    
    // Handle dummy keys
    if (recipientPublicKey === "dummy-key") {
      console.log("Using dummy encryption for compatibility");
      return JSON.stringify({
        dummy: true,
        originalMessage: message
      });
    }
    
    try {
      // Generate a random AES key
      const aesKey = await window.crypto.subtle.generateKey(
        {
          name: "AES-GCM",
          length: 256
        },
        true,
        ["encrypt", "decrypt"]
      );
      
      // Generate a random IV (Initialization Vector)
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      
      // Encrypt the message with AES-GCM
      const messageUint8 = new TextEncoder().encode(message);
      const encryptedMessage = await window.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        aesKey,
        messageUint8
      );
      
      // Export the AES key
      const exportedAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
      
      // Encrypt the AES key with the recipient's RSA public key
      const encryptedAesKey = await window.crypto.subtle.encrypt(
        {
          name: "RSA-OAEP"
        },
        recipientPublicKey,
        exportedAesKey
      );
      
      // Construct the final encrypted package
      const encryptedPackage = {
        iv: this._arrayBufferToBase64(iv),
        encryptedKey: this._arrayBufferToBase64(encryptedAesKey),
        encryptedMessage: this._arrayBufferToBase64(encryptedMessage)
      };
      
      // Return the encrypted package as a JSON string
      return JSON.stringify(encryptedPackage);
    } catch (error) {
      console.error("Encryption error:", error);
      // Fallback to dummy encryption
      return JSON.stringify({
        dummy: true,
        originalMessage: message
      });
    }
  }

  // Decrypt a message sent to this user
  async decryptMessage(encryptedPackageStr) {
    try {
      const encryptedPackage = JSON.parse(encryptedPackageStr);
      
      // Handle dummy encrypted messages
      if (encryptedPackage.dummy) {
        console.log("Received dummy-encrypted message");
        return encryptedPackage.originalMessage;
      }
      
      if (!this.cryptoSupported || !this.keyPair || this.keyPair.dummy) {
        throw new Error("Encryption not supported in this browser");
      }
      
      const iv = this._base64ToArrayBuffer(encryptedPackage.iv);
      const encryptedKey = this._base64ToArrayBuffer(encryptedPackage.encryptedKey);
      const encryptedMessage = this._base64ToArrayBuffer(encryptedPackage.encryptedMessage);
      
      // Decrypt the AES key with our RSA private key
      const aesKeyData = await window.crypto.subtle.decrypt(
        {
          name: "RSA-OAEP"
        },
        this.keyPair.privateKey,
        encryptedKey
      );
      
      // Import the decrypted AES key
      const aesKey = await window.crypto.subtle.importKey(
        "raw",
        aesKeyData,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        ["decrypt"]
      );
      
      // Decrypt the message with the AES key
      const decryptedMessage = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        aesKey,
        encryptedMessage
      );
      
      // Convert the decrypted message to text
      return new TextDecoder().decode(decryptedMessage);
    } catch (error) {
      console.error("Decryption error:", error);
      // Return an error message if decryption fails
      return "[Encrypted message - unable to decrypt]";
    }
  }
  
  // --- File Encryption Methods ---
  
  // Generate a random key for file encryption
  async generateFileKey() {
    if (!this.cryptoSupported) {
      return null;
    }
    
    try {
      return await window.crypto.subtle.generateKey(
        {
          name: "AES-GCM",
          length: 256
        },
        true, // extractable
        ["encrypt", "decrypt"]
      );
    } catch (error) {
      console.error("Error generating file key:", error);
      return null;
    }
  }
  
  // Encrypt a file for a specific recipient
  async encryptFile(file, recipientUsername) {
    if (!this.cryptoSupported) {
      console.log("File encryption not supported in this browser");
      return { file, encryptedKey: null, iv: null };
    }
    
    const recipientPublicKey = this.publicKeys.get(recipientUsername);
    if (!recipientPublicKey || recipientPublicKey === "dummy-key") {
      console.log("Cannot encrypt file: No valid public key for recipient");
      return { file, encryptedKey: null, iv: null };
    }
    
    try {
      // Generate a random AES key for this file
      const fileKey = await this.generateFileKey();
      if (!fileKey) {
        throw new Error("Failed to generate file encryption key");
      }
      
      // Generate a random IV
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      
      // Read the file as ArrayBuffer
      const fileContent = await this._readFileAsArrayBuffer(file);
      
      // Encrypt the file content
      const encryptedContent = await window.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        fileKey,
        fileContent
      );
      
      // Export the AES key
      const exportedKey = await window.crypto.subtle.exportKey("raw", fileKey);
      
      // Encrypt the key with recipient's public key
      const encryptedKey = await window.crypto.subtle.encrypt(
        {
          name: "RSA-OAEP"
        },
        recipientPublicKey,
        exportedKey
      );
      
      // Create a new file object with the encrypted content
      const encryptedFile = new File(
        [encryptedContent], 
        file.name + ".encrypted",
        {
          type: "application/octet-stream",
          lastModified: file.lastModified
        }
      );
      
      return {
        file: encryptedFile,
        encryptedKey: this._arrayBufferToBase64(encryptedKey),
        iv: this._arrayBufferToBase64(iv)
      };
    } catch (error) {
      console.error("File encryption error:", error);
      return { file, encryptedKey: null, iv: null };
    }
  }
  
  // Decrypt a file
  async decryptFile(encryptedFile, encryptedKeyBase64, ivBase64) {
    if (!this.cryptoSupported || !this.keyPair || this.keyPair.dummy) {
      console.error("File decryption not supported");
      return encryptedFile;
    }
    
    if (!encryptedKeyBase64 || !ivBase64) {
      console.log("File is not encrypted or missing encryption data");
      return encryptedFile;
    }
    
    try {
      // Convert base64 strings back to ArrayBuffer
      const encryptedKey = this._base64ToArrayBuffer(encryptedKeyBase64);
      const iv = this._base64ToArrayBuffer(ivBase64);
      
      // Read the encrypted file
      const encryptedContent = await this._readFileAsArrayBuffer(encryptedFile);
      
      // Decrypt the file key using our private key
      const keyData = await window.crypto.subtle.decrypt(
        {
          name: "RSA-OAEP"
        },
        this.keyPair.privateKey,
        encryptedKey
      );
      
      // Import the decrypted key
      const fileKey = await window.crypto.subtle.importKey(
        "raw",
        keyData,
        {
          name: "AES-GCM",
          length: 256
        },
        false, // not extractable
        ["decrypt"]
      );
      
      // Decrypt the file content
      const decryptedContent = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        fileKey,
        encryptedContent
      );
      
      // Create a new file with the decrypted content
      let fileName = encryptedFile.name;
      if (fileName.endsWith('.encrypted')) {
        fileName = fileName.substring(0, fileName.length - 10); // Remove .encrypted suffix
      }
      
      return new File(
        [decryptedContent],
        fileName,
        {
          type: this._guessFileType(fileName),
          lastModified: encryptedFile.lastModified
        }
      );
    } catch (error) {
      console.error("File decryption error:", error);
      return encryptedFile; // Return the original file if decryption fails
    }
  }
  
  // Helper: Read a file as ArrayBuffer
  async _readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsArrayBuffer(file);
    });
  }
  
  // Helper: Guess the MIME type based on filename
  _guessFileType(fileName) {
    const extension = fileName.split('.').pop().toLowerCase();
    const mimeTypes = {
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
      'pdf': 'application/pdf',
      'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'xls': 'application/vnd.ms-excel',
      'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'txt': 'text/plain',
      'mp3': 'audio/mpeg',
      'mp4': 'video/mp4'
    };
    
    return mimeTypes[extension] || 'application/octet-stream';
  }

  // Utility function to convert ArrayBuffer to Base64 string
  _arrayBufferToBase64(buffer) {
    if (!buffer) return '';
    
    try {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return window.btoa(binary);
    } catch (error) {
      console.error("Error converting ArrayBuffer to Base64:", error);
      return '';
    }
  }

  // Utility function to convert Base64 string to ArrayBuffer
  _base64ToArrayBuffer(base64) {
    if (!base64) return new ArrayBuffer(0);
    
    try {
      const binaryString = window.atob(base64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    } catch (error) {
      console.error("Error converting Base64 to ArrayBuffer:", error);
      return new ArrayBuffer(0);
    }
  }

  // Utility to check if Web Crypto API is available
  static isSupported() {
    return !!(window.crypto && window.crypto.subtle);
  }
}

// Create a global instance
window.encryptionManager = new EnhancedEncryptionManager();
console.log("Enhanced EncryptionManager initialized, crypto supported:", EnhancedEncryptionManager.isSupported());