import { Controller, Get, Delete, Param, UseGuards, Req} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { UserRepository } from './user.repository';


@UseGuards(JwtAuthGuard)
@Controller('user')
export class UserController {
  constructor(private readonly userRepository: UserRepository) {}
  
  @UseGuards(JwtAuthGuard)
  @Get('all')
  async getAllUsers(@Req() req: any) {
    console.log('🔐 req.user:', req.user);
    const users = await this.userRepository.getAllUsers();
    return users;
  }

  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  async deleteUser(@Param('id') id: number, @Req() req: any) {
    const requestingUser = req.user;

    if (!requestingUser) {
      throw new Error('Не удалось получить пользователя из токена');
    }

    if (requestingUser.id === id) {
      throw new Error('Невозможно удалить самого себя');
    }

    const user = await this.userRepository.getUserById(id);
    if (!user) {
      throw new Error('Пользователь не найден');
    }

    await this.userRepository.deleteUser(user);
    return { message: 'Пользователь удален' };
  }
}
