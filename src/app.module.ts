import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user/user.entity';
import { AuthModule } from './auth/auth.module';
import { KeyModule } from './key/key.module';
import { UserRepository } from './user/user.repository';
import { UserController } from './user/user.controller';
import {config} from 'dotenv';

 
config()

@Module({
  imports: [ 
    TypeOrmModule.forRoot({
      type: 'sqlite',
      database: 'secure.db',
      entities: [User],
      synchronize: true
    }),
    TypeOrmModule.forFeature([User]),
    AuthModule,
    KeyModule
  ],
  controllers: [UserController],
  providers: [UserRepository],
})
export class AppModule {}