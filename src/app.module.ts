import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user/user.entity';
import { AuthModule } from './auth/auth.module';
import { KeyModule } from './key/key.module';
import { KeyController } from './key/key.controller';
import { AuthController } from './auth/auth.controller';
import { KeyService } from './key/key.service';
import { AuthService } from './auth/auth.service';

@Module({
  imports: [  
    TypeOrmModule.forRoot({
      type: 'sqlite',
      database: 'secure.db',
      entities: [User],
      synchronize: true
    }),
    TypeOrmModule.forFeature([User]),
    // AuthModule,
    // KeyModule
  ],
  controllers: [KeyController, AuthController],//
  providers: [KeyService, AuthService],//
})
export class AppModule {}