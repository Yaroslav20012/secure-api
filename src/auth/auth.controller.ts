import { Controller, Post, Body, Res, Request } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import * as jwt from 'jsonwebtoken';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService
  ) {}

  @Post('register')
  async register(@Body() dto: { email: string; password: string }) {
    try {
      const decryptedEmail = this.authService.decryptWithPrivateKey(dto.email);
      const decryptedPassword = this.authService.decryptWithPrivateKey(dto.password);

      if (!decryptedEmail || !decryptedPassword) {
        throw new Error('Не удалось расшифровать данные');
      }

      await this.authService.register(decryptedEmail, decryptedPassword);
      return { message: 'Регистрация успешна' };
    } catch (e) {
      console.error('Ошибка регистрации:', e.message);
      throw new Error('Не удалось зарегистрировать пользователя');
    }
  }

  @Post('login')
  async login(

    @Body() dto: { email: string; password: string },
    @Res({ passthrough: true }) response: Response
  ) {

    console.log('📩 Запрос на вход:', dto); 

    const decryptedEmail = this.authService.decryptWithPrivateKey(dto.email);
    const decryptedPassword = this.authService.decryptWithPrivateKey(dto.password);


    console.log('🔓 Расшифрованный email:', decryptedEmail);
    console.log('🔓 Расшифрованный пароль:', decryptedPassword);


    if (!decryptedEmail || !decryptedPassword) {
      console.error('🚫 Не удалось расшифровать данные');
      throw new Error('Не удалось расшифровать данные');
    }

    const user = await this.authService.validateUser(decryptedEmail, decryptedPassword);
    const tokens = this.authService.generateTokens(user);


    console.log('🔑 Сгенерированный токен:', tokens.accessToken);
    console.log('🍪 Установлен refresh_token в куку');


    response.cookie('refresh_token', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 дней
    });

    console.log('Сгенерирован refresh_token', tokens.refreshToken);

    console.log('🔐 JWT_SECRET:', process.env.JWT_SECRET);
    console.log('🔐 REFRESH_TOKEN_SECRET:', process.env.JWT_REFRESH_SECRET);

    return {
      token: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      email: user.email,
      id: user.id,
      role: user.role
    };
  }

  @Post('refresh')
  async refresh(@Request() req, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies['refresh_token'] || req.headers['x-refresh-token'];

    if (!refreshToken) {
      throw new Error('Refresh token отсутствует');
    }
    

    const refreshTokenSecret = process.env.JWT_REFRESH_SECRET;
    if (!refreshTokenSecret) {
      throw new Error('JWT_REFRESH_SECRET не установлен');
    } 

    try {
      const decoded = jwt.verify(refreshToken, refreshTokenSecret);
      const user = await this.authService.validateUserByToken(decoded);
      const tokens = this.authService.generateTokens(user);

      res.cookie('refresh_token', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      return { accessToken: tokens.accessToken };
    } catch (e) {
      console.error('Ошибка обновления токена:', e.message);
      throw new Error('Не удалось обновить токен');
    }
  }
}