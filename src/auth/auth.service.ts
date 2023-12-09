import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config/dist/config.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

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
      return this.signToken(user.Id, user.email);
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
    return this.signToken(user.Id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = await this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(payload, {
      secret: 'superSecret',
      expiresIn: '30m',
    });

    return {
      access_token: token,
    };
  }
}
