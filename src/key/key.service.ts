import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

@Injectable()
export class KeyService {
  private readonly keyDir = path.resolve(__dirname, '..', 'keys');

  private readonly publicKeyPath = path.resolve(__dirname, '..', 'keys', 'public.pem');
  private readonly privateKeyPath = path.resolve(__dirname, '..', 'keys', 'private.pem');

  public publicKey!: string;
  public privateKey!: string;

  constructor() {
    this.loadKeys();
  }

  private loadKeys(): void {
    
    // Проверяем, существуют ли директория и файлы ключей
    if (!fs.existsSync(this.keyDir)) {
      fs.mkdirSync(this.keyDir, { recursive: true }); // создаем директорию, если её нет
    }

    try {
      // Генерация ключей, если они отсутствуют
      if (!fs.existsSync(this.publicKeyPath) || !fs.existsSync(this.privateKeyPath)) {
        this.generateKeys(this.publicKeyPath, this.privateKeyPath);
      }

      // Чтение ключей из файлов
      this.publicKey = fs.readFileSync(this.publicKeyPath, 'utf8');
      this.privateKey = fs.readFileSync(this.privateKeyPath, 'utf8');

    } catch (err) {
      console.error('Ошибка загрузки ключей:', err.message);
      throw new Error('Не могу загрузить ключи. Убедитесь, что public.pem и private.pem существуют в папке keys/');
    }
  }

  private generateKeys(publicKeyPath: string, privateKeyPath: string): void {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    // Запись ключей в файлы
    fs.writeFileSync(publicKeyPath, publicKey);
    fs.writeFileSync(privateKeyPath, privateKey);
    console.log('Новые ключи сгенерированы и сохранены.');
  }

  getPublicKey(): string {
    return fs.readFileSync(this.publicKeyPath, 'utf8');
  }

  getPrivateKey(): string {
    return fs.readFileSync(this.privateKeyPath, 'utf8');
  }

  async decrypt(data: string): Promise<string> {
    try {
      const bufferData = Uint8Array.from(atob(data), c => c.charCodeAt(0));

      const pemHeader = '-----BEGIN PRIVATE KEY-----';
      const pemFooter = '-----END PRIVATE KEY-----';
      const pemContents = this.privateKey
        .replace(pemHeader, '')
        .replace(pemFooter, '')
        .replace(/\s/g, '');

      const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

      const privateKey = await window.crypto.subtle.importKey(
        'pkcs8',
        binaryDer.buffer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt']
      );

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        bufferData
      );

      return new TextDecoder().decode(decryptedBuffer);
    } catch (e) {
      console.error('Ошибка расшифровки:', e.message);
      throw new Error('Не удалось расшифровать данные');
    }
  }
}
