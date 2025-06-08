import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from '../user/user.entity';
import { JwtStrategy } from './jwt.strategy';
import { JwtModule} from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { SanitizerService } from 'src/utils/sanitizer.service';



@Module({
  imports: [
    TypeOrmModule.forFeature([User]), 
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({})
    
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, SanitizerService],
  exports: [AuthService, SanitizerService]
})
export class AuthModule {

  constructor(){
    console.log('🔐 AuthModule загружен');
    console.log('🗝️ JWT_SECRET:', process.env.JWT_SECRET ? '✅ Установлен' : '❌ Не задан');
  }


}
