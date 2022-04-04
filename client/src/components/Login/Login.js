import React from 'react'
import { Link } from "react-router-dom"
import { useState } from "react"
import axios from 'axios'
import { setToken, removeToken } from '../utils/authOperations'

import "./login.css"

function Login() {
  removeToken()
  const [user, setUser] = useState({
    email: "",
    password: "",
  })


  const onSubmit = e => {
    e.preventDefault();
    const userData = {
      email: user.email,
      password: user.password
    };

    axios.post("http://localhost:5000/api/user/login", userData)
      .then(res => {
        console.log(res);
        if (res.data === "User Does Not Exist!") {
          alert("User Does Not Exist!")
          window.location.href = "/register";
        } else if(res.data === "Incorrect Password!"){
          alert("Incorrect Password!")
          window.location.href = "/";
        }
        else {
          const token = res.data
          setToken(token)
          window.location.href = "/products";
        }

      })
      .catch(err => console.log(err)
      );
  };

  return (
    <div className='login__main'>

      <div className="login__header">
        <h4 className='login__title'>
          <b>Login</b> to your account
        </h4>

      </div>
      <form noValidate onSubmit={onSubmit}>
        <div>
          <label className='form__label' htmlFor="email">Email</label>
          <input className='form__input'
            onChange={(e) => setUser({ ...user, email: e.target.value })}
            value={user.email}
            id="email"
            type="email"
          />

        </div>
        <div>
          <label className='form__label' htmlFor="password">Password</label>
          <input className='form__input'
            onChange={(e) => setUser({ ...user, password: e.target.value })}
            value={user.password}
            id="password"
            type="password"
          />

        </div>
        <div className='submit'>
          <button className='form__button' type="submit">Login </button>
        </div>
      </form>
      <p className='login__subtitle'>
        Don't have an account? <Link to="/register" className='button'>Sign Up</Link>
      </p>
    </div>

  );
}

export default Login

