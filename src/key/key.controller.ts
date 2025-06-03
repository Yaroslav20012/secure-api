import { Controller, Get } from '@nestjs/common';
import { KeyService } from './key.service';

@Controller('key')
export class KeyController {
  constructor(private keyService: KeyService) {}

  @Get('public-key')
  getPublicKey() {
    return this.keyService.getPublicKey();
  }
}