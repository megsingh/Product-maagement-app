import React from 'react'
import { useState, useHistory } from 'react';
import { Link } from "react-router-dom"
import axios from "axios"
import { removeToken } from '../utils/authOperations';
import "../Login/login.css"

function Register() {
    removeToken()
    const history = useHistory
    const [user, setUser] = useState({
        name: "",
        email: "",
        password: "",
    })

    const onSubmit = e => {
        e.preventDefault();
        const newUser = {
            name: user.name,
            email: user.email,
            password: user.password
        };
        console.log(newUser);
        console.log("inside on submit");
        axios.post("http://localhost:5000/api/user/register", newUser)
            .then(res => {
                console.log(res);
                if (res.data === "User Already Exists!") {
                    alert("User Already Exists!")
                    window.location.href = "/";
                } else{
                    window.location.href = "/";
                }  
            }) // re-direct to login on successful register
            .catch(err => console.log(err)
            );
    };



    return (
        <div className='login__main'>
            <div className="login__header">
                <h4 className='login__title'>
                    <b>Register</b>
                </h4>

            </div>
            <form noValidate onSubmit={onSubmit}>
                <div>
                    <label className='form__label'>Name</label>
                    <input className='form__input'
                        onChange={(e) => setUser({ ...user, name: e.target.value })}
                        value={user.name}
                        id="name"
                        type="text"
                    />

                </div>
                <div>
                    <label className='form__label'>Email</label>
                    <input className='form__input'
                        onChange={(e) => setUser({ ...user, email: e.target.value })}
                        value={user.email}
                        id="email"
                        type="email"
                    />
                </div>
                <div>
                    <label className='form__label'>Password</label>
                    <input className='form__input'
                        onChange={(e) => setUser({ ...user, password: e.target.value })}
                        value={user.password}
                        id="password"
                        type="password"
                    />

                </div>

                <div className='submit'>
                    <button className='form__button' type="submit">Sign up</button>
                </div>
            </form>
            <p className='login__subtitle'>
                Already have an account? <Link className='button' to="/">Login</Link>
            </p>
        </div>


    );
}


export default Register;

