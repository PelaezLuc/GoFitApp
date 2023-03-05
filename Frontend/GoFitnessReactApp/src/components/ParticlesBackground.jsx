import React, { useCallback } from 'react';
import './css/particles.css';
import Particles from 'react-tsparticles';
import { loadFull } from 'tsparticles';
import particlesConfig from './config/particles-config';

const ParticlesBackground = () => {

    const particlesInit = useCallback((engine) => {
        loadFull(engine)
    }, {})

    return (
        <div class="particles-bg">
            <Particles
             //id="tsparticles"
             options={particlesConfig}   
             init={particlesInit}
            />
        </div>
    );
};

export default ParticlesBackground;