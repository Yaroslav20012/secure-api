import { Controller, Get, Param } from '@nestjs/common';
import { UserRepository } from './user.repository';

@Controller('user')
export class UserController {
  constructor(private readonly userRepository: UserRepository) {}

  @Get('all')
  async getAllUsers() {
    return {
      users: await this.userRepository.getAllUsers()
    };
  }

  @Get(':id')
  async getUserById(@Param('id') id: number) {
    const user = await this.userRepository.getUserById(id);
    if (!user) {
      throw new Error('Пользователь не найден');
    }
    return user;
  }
}