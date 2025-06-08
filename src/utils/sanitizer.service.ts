
import { Injectable } from '@nestjs/common';
import * as DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

@Injectable()
export class SanitizerService {
  private purify;

  constructor() {
    const window = new JSDOM('').window;
    this.purify = DOMPurify(window);
  }

  sanitize(input: string): string {
    return this.purify.sanitize(input);
  }
}
