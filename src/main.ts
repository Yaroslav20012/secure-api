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

  app.use((req, res, next) => {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; " +
        "script-src 'self' https://cdnjs.cloudflare.com;  " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "connect-src 'self'; " +
        "font-src 'self'; " +
        "object-src 'none'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self';"
    );
    next();
  });
  
  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe());

  app.setGlobalPrefix('api');
  
  await app.listen(3000);
}

bootstrap();