import { Controller, Get, Delete, Param, UseGuards, Request, Req} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { UserRepository } from './user.repository';
import { User } from './user.entity';

@Controller('user')
@UseGuards(JwtAuthGuard)
export class UserController {
  constructor(private readonly userRepository: UserRepository) {}

  // @Get('all')
  // async getAllUsers(@Request() req) {
  //   return { users: await this.userRepository.getAllUsers() };
  // }

  // @Delete(':id')
  // async deleteUser(@Param('id') id: number, @Request() req: any) {
  //   const requestingUser = req.user as any;

  //   if (requestingUser.id === id) {
  //     throw new Error('Администратор не может удалить себя');
  //   }

  //   const user = await this.userRepository.getUserById(id);
  //   if (!user) {
  //     throw new Error('Пользователь не найден');
  //   }

  //   await this.userRepository.deleteUser(user);
  //   return { message: 'Пользователь удален' };
  // }

  @Get('all')
  // @UseGuards(JwtAuthGuard)
  async getAllUsers(@Req() req) {
    console.log('Пользователь из токена:', req.user);
    return {
      users: await this.userRepository.getAllUsers()
    };
  }

  @Delete(':id')
  // @UseGuards(JwtAuthGuard)
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