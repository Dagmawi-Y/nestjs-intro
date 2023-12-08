import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    // generate the password hash
    const hash = await argon.hash(dto.password);

    // save the new user in DB

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      delete user.hash;

      // return the saved user
      return user;
    } catch (e) {
      if (e instanceof PrismaClientKnownRequestError) {
        if (e.code === 'P2002') {
          throw new ForbiddenException('Credentials Taken.');
        }
        throw e;
      }
    }
  }

  async signin(dto: AuthDto) {
    // find the user
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // is user doesn't exist throw error and return
    if (!user) throw new ForbiddenException('Credentials incorrect.');

    // check password
    const pwMatch = await argon.verify(user.hash, dto.password);
    // if it doesn't match throw an error
    if (!pwMatch) throw new ForbiddenException('Credentials incorrect.');

    delete user.hash;
    // return user
    return user;
  }
}
