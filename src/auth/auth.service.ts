
import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs'

import { User } from './entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt.payload';
import { LoginResponse } from './interfaces/login-response';

import { CreateUserDto,UpdateAuthDto, LoginDto, RegisterUserDto } from './dto/';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService,
  ){}


  async create(createUserDto: CreateUserDto) {
   
    
    try{
      const{password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10), 
        ...userData
      });

      await newUser.save();
      const {password:_, ...user} = newUser.toJSON(); 
      return user;

    }catch (error){
      if(error.code === 11000){
        throw new BadRequestException(`${createUserDto.email} already exists`);
      }
      console.log(error.code);
    }
    throw new InternalServerErrorException('Something terrible happen!!!')
    

  }

  async register(regiserterDto: RegisterUserDto): Promise<LoginResponse>{
    const user = await this.create(regiserterDto);

    return{
      user: user, 
      token: this.getJWToken({id: user._id } ),
    }

  } 

  async login(loginDto: LoginDto):  Promise<LoginResponse>{
    // 1 -Verificar el email y contraseña>
    const {email, password} =loginDto;
    const user = await this.userModel.findOne({email});
    if (!user ){
      throw new UnauthorizedException('Not valid credentials ');
    }
    if(!bcryptjs.compareSync(password, user.password)){
      throw new UnauthorizedException('Not valid credentials ');
    }

    const {password: _, ...rest} = user.toJSON();
    return {
      user: rest, 
      token: this.getJWToken({id: user.id } ),
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id:  string){
    const user = await this.userModel.findById(id);
    
    const {password,  ...rest } = user.toJSON();

    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWToken(paylod: JwtPayload){
    const token = this.jwtService.sign(paylod);
    return token;

  }
}
