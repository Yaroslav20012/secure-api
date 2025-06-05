import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'your-secret-here'
    });
  }

  async validate(payload: any) {
    
    if (!payload?.email || !payload?.id) {
      throw new Error('Неверные данные в токене');
    }

    console.log('🧾 Payload из токена:', payload);
    return {
      id: Number(payload.id),
      email: payload.email,
      role: payload.role || 'user'
    };
  }
}