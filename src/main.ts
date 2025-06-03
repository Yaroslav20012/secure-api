import { NestFactory } from '@nestjs/core';
import { AppModule } from 'src/app.module';
import { config } from 'dotenv';


config(); // загрузка .env

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api');
  
  app.enableCors({
    origin: 'http://localhost:4200',
    credentials: true
  });

  await app.listen(3000);
}

bootstrap();