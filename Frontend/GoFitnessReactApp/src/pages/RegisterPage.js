import './css/form.css';
import {Link, useNavigate} from 'react-router-dom';
import { Footer } from '../components/Footer';
import { registerUserService } from '../services/services';
import { useState } from 'react';
import ParticlesBackground from '../components/ParticlesBackground';


export const RegisterPage = () => {
    
    const navigate = useNavigate();

    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    
    const handleForm = async (e) => {
        e.preventDefault();
        setError('');

        try {
            await registerUserService({name, email, password});

            navigate('/login');
        } catch (error) {
            setError(error.message);
        }
    }
    return (
        <>
        {/* <ParticlesBackground /> */}
        <section className="register">
             <Link to={"/"}><h2>GoFit<span className="font-family-app">APP</span></h2>    
               </Link>  
                <h4>Regístrate</h4>
            <form className="form" onSubmit={handleForm}>
                <div className="group">
                    <input 
                        className="controls" 
                        type="text" 
                        name="name" 
                        id="name" 
                        required 
                        onChange={(e) => setName(e.target.value)}
                    />
                    <label className="form-label" htmlFor="name">Nombre de usuario</label>
                </div>
                <div className="group">
                    <input 
                        className="controls" 
                        type="text" 
                        name="email" 
                        id="email" 
                        required
                        onChange={(e) => setEmail(e.target.value)}
                    />
                    <label className="form-label" htmlFor="email">Email</label>
                </div>
                <div className="group">
                    <input 
                        className="controls" 
                        type="password" 
                        name="password" 
                        id="password" 
                        required
                        onChange={(e) => setPassword(e.target.value)}
                    />
                    <label className="form-label" htmlFor="password">Contraseña</label>
                </div>
                <Link to='/login'>¿Ya tienes una cuenta?</Link>
                <input className="btn" type="submit" value="Registrar"/>
                {error ? <p>{error}</p> : null}
            </form>
        </section>
        <Footer />
        </>
    )
}