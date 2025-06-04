// import { Module } from '@nestjs/common';
// import { TypeOrmModule } from '@nestjs/typeorm';
// import { AuthService } from './auth.service';
// import { AuthController } from './auth.controller';
// import { User } from 'src/user/user.entity';
// import { JwtStrategy } from './jwt.strategy';
// import { PassportModule } from '@nestjs/passport';
// import { JwtModule } from '@nestjs/jwt';


// @Module({
//   imports: [
//     JwtModule.register({}), 
//     TypeOrmModule.forFeature([User]), 
//     PassportModule.register({ defaultStrategy: 'jwt' })
//   ],
//   controllers: [AuthController],
//   providers: [PassportModule, AuthService, JwtStrategy],
//   exports: [AuthService]
// })
// export class AuthModule {}
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from '../user/user.entity';
import { JwtStrategy } from './jwt.strategy';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]), 
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'your-secret-here' , // Убедитесь, что секрет установлен
      signOptions: { expiresIn: '15m' },
    }),     
    PassportModule.register({ defaultStrategy: 'jwt' })
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [AuthService]
})
export class AuthModule {}
