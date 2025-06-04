  // import { Controller, Post, Body, Res, UseGuards } from '@nestjs/common';
  // import { Request, Response } from 'express';
  // import { AuthGuard } from '@nestjs/passport';
  // import { AuthService } from './auth.service';
  // import { InjectRepository } from '@nestjs/typeorm';
  // import { Repository } from 'typeorm';
  // import { User } from '../user/user.entity';

  // @Controller('auth')
  // export class AuthController {
  //   constructor(
  //     private readonly authService: AuthService,
  //     // @InjectRepository(User)
  //     // private readonly userRepository: Repository<User>
  //   ) {}

  //   @Post('register')
  //   async register(@Body() dto: { email: string; password: string }) {
  //     try {
  //       const decryptedEmail = this.authService.decryptWithPrivateKey(dto.email);
  //       const decryptedPassword = this.authService.decryptWithPrivateKey(dto.password);

  //       if (!decryptedEmail || !decryptedPassword) {
  //         throw new Error('Ошибка расшифровки');
  //       }

  //       // const existingUser = await this.userRepository.findOneBy({ email: decryptedEmail });
  //       // if (existingUser) {
  //       //   throw new Error('Пользователь уже существует');
  //       // }
        
  //       await this.authService.register(decryptedEmail, decryptedPassword);
  //       return { message: 'Регистрация успешна' };
  //     } catch (e) {
  //       console.error('Ошибка регистрации:', e.message);
  //       throw new Error('Не удалось зарегистрировать пользователя');
  //     }
  //   }

  //   @Post('login')
  //   async login(
  //     @Body() dto: { email: string; password: string },
  //     @Res({ passthrough: true }) response: Response
  //   ) {
  //     const decryptedEmail = this.authService.decryptWithPrivateKey(dto.email);
  //     const decryptedPassword = this.authService.decryptWithPrivateKey(dto.password);

  //     if (!decryptedEmail || !decryptedPassword) {
  //       throw new Error('Не удалось расшифровать данные');
  //     }

  //     const user = await this.authService.validateUser(decryptedEmail, decryptedPassword);
  //     const tokens = this.authService.generateTokens(user.email, user.id);

  //     response.cookie('refresh_token', tokens.refreshToken, {
  //       httpOnly: true,
  //       secure: process.env.NODE_ENV === 'production',
  //       sameSite: 'strict',
  //       maxAge: 7 * 24 * 60 * 60 * 1000
  //     });

  //     return {
  //       token: tokens.accessToken,
  //       refreshToken: tokens.refreshToken,
  //       email: user.email,
  //       id: user.id
  //     };
  //   }
  // }
  import { Controller, Post, Body, Res } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() dto: { email: string; password: string }) {
    try {
      const decryptedEmail = this.authService.decryptWithPrivateKey(dto.email);
      const decryptedPassword = this.authService.decryptWithPrivateKey(dto.password);

      if (!decryptedEmail || !decryptedPassword) {
        throw new Error('Не удалось расшифровать данные');
      }

      await this.authService.register({ email: decryptedEmail, password: decryptedPassword });
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
    const decryptedEmail = this.authService.decryptWithPrivateKey(dto.email);
    const decryptedPassword = this.authService.decryptWithPrivateKey(dto.password);

    if (!decryptedEmail || !decryptedPassword) {
      throw new Error('Не удалось расшифровать данные');
    }

    const user = await this.authService.validateUser(decryptedEmail, decryptedPassword);
    const tokens = this.authService.generateTokens({ email: user.email, id: user.id });

    response.cookie('refresh_token', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return {
      token: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      email: user.email,
      id: user.id
    };
  }
}