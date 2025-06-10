import { NestFactory } from '@nestjs/core';
import { AppModule } from 'src/app.module';
import { config } from 'dotenv';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';


config(); // загрузка .env

async function bootstrap() {
  const app = await NestFactory.create(AppModule);


  console.log('🌐 CORS настроен на:', 'https://secure-angular-app.onrender.com');
  console.log('📦 API Prefix:', 'api');
  console.log('📁 NODE_ENV:', process.env.NODE_ENV);


  app.enableCors({
    origin: 'https://secure-angular-app.onrender.com',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: ['Authorization', 'Content-Type'],
  });
  
  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe());

  app.setGlobalPrefix('api');
  
  await app.listen(3000);
}

bootstrap();