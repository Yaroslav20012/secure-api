import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import { User } from '../user/user.entity';

@Injectable()
export class AuthService {
  private readonly privateKey = fs.readFileSync(
    path.resolve(__dirname, '..', 'keys', 'private.pem'),
    'utf8'
  );

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>
  ) {}

  decryptWithPrivateKey(data: string): string {
    try {
      const bufferData = Buffer.from(data, 'base64');

      const decrypted = crypto.privateDecrypt(
        {
          key: this.privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        bufferData
      );

      return decrypted.toString('utf8');
    } catch (e) {
      console.error('Не удалось расшифровать данные:', e.message);
      throw new Error('Ошибка расшифровки данных');
    }
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userRepository.findOneBy({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new Error('Неверные учетные данные');
    }

    return user;
  }

  generateTokens(email: string, id: number) {
    const payload = { email, id };
    const accessToken = Buffer.from(JSON.stringify(payload)).toString('base64');
    const refreshToken = Buffer.from(JSON.stringify(payload)).toString('base64');

    return { accessToken, refreshToken };
  }

  async register(email: string, password: string): Promise<void> {
    const existingUser = await this.userRepository.findOneBy({ email });
    if (existingUser) {
      throw new Error('Пользователь уже существует');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = this.userRepository.create({ email, password: hashedPassword });
    await this.userRepository.save(newUser);
  }
}