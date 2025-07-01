async function generateRSAKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  const pubKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  const privKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  return {
    publicKey: arrayBufferToPem(pubKey, "PUBLIC KEY"),
    privateKey: arrayBufferToPem(privKey, "PRIVATE KEY")
  };
}

function arrayBufferToPem(buffer, type) {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  const base64 = btoa(binary);
  const formatted = base64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${type}-----\n${formatted}\n-----END ${type}-----`;
}

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----(BEGIN|END) [A-Z ]+-----/g, '').replace(/\s/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

document.getElementById('generateKeys').addEventListener('click', async () => {
  const keys = await generateRSAKeyPair();
  document.getElementById('senderPublicKey').value = keys.publicKey;
  document.getElementById('senderPrivateKey').value = keys.privateKey;
  document.getElementById('log').value += "Đã tạo cặp khóa RSA cho Người Gửi.\n";
});

let encryptedFile = null;

document.getElementById('sendFile').addEventListener('click', async () => {
  const file = document.getElementById('fileInput').files[0];
  if (!file) {
    alert("Chọn file trước!");
    return;
  }

  const pubPem = document.getElementById('receiverPublicKey').value;
  const pubKey = await window.crypto.subtle.importKey(
    "spki",
    pemToArrayBuffer(pubPem),
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["encrypt"]
  );

  const arrayBuffer = await file.arrayBuffer();
  try {
    encryptedFile = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      pubKey,
      arrayBuffer
    );

    document.getElementById('log').value += `Đã mã hóa file: ${file.name}\n`;
    document.getElementById('result').value = btoa(String.fromCharCode(...new Uint8Array(encryptedFile)));
  } catch (e) {
    alert("File quá lớn cho RSA. RSA chỉ mã hóa tối đa vài trăm byte.");
  }
});

document.getElementById('receiveFile').addEventListener('click', async () => {
  if (!encryptedFile) {
    alert("Chưa có file mã hóa!");
    return;
  }

  const privPem = document.getElementById('receiverPrivateKey').value;
  const privKey = await window.crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(privPem),
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["decrypt"]
  );

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privKey,
      encryptedFile
    );

    const decoder = new TextDecoder();
    document.getElementById('fileContent').value = decoder.decode(decrypted);
    document.getElementById('log').value += "Đã giải mã file.\n";
  } catch (e) {
    alert("Giải mã thất bại!");
  }
});
