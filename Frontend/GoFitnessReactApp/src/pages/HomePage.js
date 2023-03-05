import './css/homePage.css';
import { Link } from 'react-router-dom';
import { HeaderNav } from '../components/HeaderNav';


export const HomePage = () => {
    return (
        <>
        <header className="homepage-header">
            <h1 className='header-title'>GoFit<span className="app-text">APP</span></h1>
            <HeaderNav />
        </header>
        <section id="landing">
            <article className="landing-div">
                <h3>Traning App</h3>

                <p>Crea y monitoriza tus sesiones de entrenamiento</p>

                <div className='btn-container'>
                    <Link to={'/login'}>
                        <button className="landing-button">Login</button>
                    </Link>
                    <Link to={'/register'}>
                        <button className="landing-button">Registro</button>
                    </Link>
                </div>
            </article>
        </section>
        <footer className="homepage-footer">
        <p>GoFitness APP | 2023 | Daniel Otero - Lucas Peláez | Hack A Boss</p>
    </footer>
    </>
    )
}