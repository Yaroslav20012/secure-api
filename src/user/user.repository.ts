import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class UserRepository {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>
  ) {}

  async findUserByEmail(email: string): Promise<User | null> {
    return await this.userRepo.findOneBy({ email });
  }

  // async saveUser(user: Partial<User>): Promise<User> {
  //   const newUser = this.userRepo.create(user);
  //   return await this.userRepo.save(newUser);
  // }

  async getAllUsers(): Promise<User[]> {
    return await this.userRepo.find({});
  }

  async getUserById(id: number): Promise<User | null> {
    return await this.userRepo.findOneBy({ id });
  }

  async deleteUser(user: User): Promise<void> {
    await this.userRepo.remove(user);
  }
}