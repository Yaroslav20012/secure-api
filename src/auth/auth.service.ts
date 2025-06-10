import { BadRequestException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
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
    private readonly userRepo: Repository<User>,
    private readonly jwtService: JwtService
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userRepo.findOneBy({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new Error('Неверные учетные данные');
    }
    return user;
  }

  decryptWithPrivateKey(data: string): string {
    try {

      
      console.log('📥 Получены зашифрованные данные:', data);


      const bufferData = Buffer.from(data, 'base64');
      const decrypted = crypto.privateDecrypt(
        {
          key: this.privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        bufferData
      );

      const result = decrypted.toString('utf8');
      console.log('🔓 Расшифровано:', result);
      return result;

    } catch (e) {
      console.error('Не удалось расшифровать данные:', e.message);
      throw new Error('Ошибка расшифровки данных');
    }
  }

  generateTokens(user: User) {
    const tokenPayload = {
      email: user.email,
      id: String(user.id),
      role: user.role
    };

    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET не задан в .env');
    }

    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: process.env.JWT_SECRET || 'your-secret-here',
      expiresIn: '15m'
    });

    const refreshToken = this.jwtService.sign(tokenPayload, {
      secret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-here',
      expiresIn: '7d'
    });

    return { accessToken, refreshToken };
  }


  async register( email: string, password: string) {
    const existingUser = await this.userRepo.findOneBy({ email });
    if (existingUser) {
      throw new BadRequestException('Некорректные данные');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = this.userRepo.create({
      email,
      password: hashedPassword
    });

    await this.userRepo.save(newUser);
    return this.generateTokens(newUser);

  }


  async validateUserByToken(decoded: any): Promise<any> {
  const user = await this.userRepo.findOneBy({ email: decoded.email });
  if (!user || Number(user.id) !== Number(decoded.id)) {
    throw new Error('Пользователь из токена не найден');
  }
  return user;
}
}